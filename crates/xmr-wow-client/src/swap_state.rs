/// Swap state and timelock rules for the XMR<->WOW protocol.
use serde::{Deserialize, Serialize};
use crate::guarantee::{guarantee_decision, GuaranteeMode, GuaranteeStatus};
use crate::readiness::{
    RefundCheckpoint, RefundCheckpointName, RefundCheckpointStatus, RefundEvidence,
};
use xmr_wow_wallet::{RefundArtifact, RefundArtifactMetadata, RefundChain, TxHash};
use xmr_wow_crypto::{
    combine_public_keys, derive_view_key, joint_address, keccak256, AdaptorSignature,
    CompletedSignature, DleqProof, KeyContribution, Network,
};
/// The role of this party in the swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapRole {
    Alice,
    Bob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefundTimingSource {
    DaemonHeightQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundTimingObservation {
    pub xmr_base_height: u64,
    pub wow_base_height: u64,
    pub xmr_lock_blocks: u64,
    pub wow_lock_blocks: u64,
    pub source: RefundTimingSource,
}

/// Swap parameters agreed during setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapParams {
    pub amount_xmr: u64,
    pub amount_wow: u64,
    pub xmr_refund_height: u64,
    pub wow_refund_height: u64,
    #[serde(default)]
    pub refund_timing: Option<RefundTimingObservation>,
    /// Alice refund address if the swap aborts.
    pub alice_refund_address: Option<String>,
    /// Bob refund address if the swap aborts.
    pub bob_refund_address: Option<String>,
}

/// Minimum gap between Alice's XMR refund and Bob's WOW refund.
pub const MIN_RESPONSE_BLOCKS: u64 = 100;

/// Compute refund heights and enforce the minimum lock window.
pub fn validate_timelocks(
    current_xmr_height: u64,
    current_wow_height: u64,
    xmr_lock_blocks: u64,
    wow_lock_blocks: u64,
) -> Result<(u64, u64), SwapError> {
    let xmr_refund_height = current_xmr_height + xmr_lock_blocks;
    let wow_refund_height = current_wow_height + wow_lock_blocks;
    if xmr_lock_blocks < 10 || wow_lock_blocks < 10 {
        return Err(SwapError::InvalidTimelock(
            "lock period too short (min 10 blocks)".into(),
        ));
    }
    if wow_refund_height <= xmr_refund_height + MIN_RESPONSE_BLOCKS {
        return Err(SwapError::InvalidTimelock(format!(
            "WOW refund height ({}) must be > XMR refund height ({}) + MIN_RESPONSE_BLOCKS ({})",
            wow_refund_height, xmr_refund_height, MIN_RESPONSE_BLOCKS
        )));
    }
    Ok((xmr_refund_height, wow_refund_height))
}

pub fn build_observed_refund_timing(
    current_xmr_height: u64,
    current_wow_height: u64,
    xmr_lock_blocks: u64,
    wow_lock_blocks: u64,
) -> Result<(RefundTimingObservation, u64, u64), SwapError> {
    let (xmr_refund_height, wow_refund_height) = validate_timelocks(
        current_xmr_height,
        current_wow_height,
        xmr_lock_blocks,
        wow_lock_blocks,
    )?;

    Ok((
        RefundTimingObservation {
            xmr_base_height: current_xmr_height,
            wow_base_height: current_wow_height,
            xmr_lock_blocks,
            wow_lock_blocks,
            source: RefundTimingSource::DaemonHeightQuery,
        },
        xmr_refund_height,
        wow_refund_height,
    ))
}

impl SwapParams {
    pub fn require_observed_refund_timing(&self) -> Result<&RefundTimingObservation, SwapError> {
        self.refund_timing.as_ref().ok_or_else(|| {
            SwapError::InvalidTimelock(
                "Phase 13 timing basis missing: legacy swap state does not record refund_timing"
                    .into(),
            )
        })
    }

    pub fn validate_observed_refund_timing(&self) -> Result<(), SwapError> {
        let observation = self.require_observed_refund_timing()?;
        let (_, expected_xmr_refund_height, expected_wow_refund_height) =
            build_observed_refund_timing(
                observation.xmr_base_height,
                observation.wow_base_height,
                observation.xmr_lock_blocks,
                observation.wow_lock_blocks,
            )?;

        if self.xmr_refund_height != expected_xmr_refund_height
            || self.wow_refund_height != expected_wow_refund_height
        {
            return Err(SwapError::InvalidTimelock(format!(
                "Phase 13 timing basis mismatch: stored heights ({}, {}) do not match observed basis ({}, {})",
                self.xmr_refund_height,
                self.wow_refund_height,
                expected_xmr_refund_height,
                expected_wow_refund_height,
            )));
        }

        Ok(())
    }
}

/// Public key contribution plus DLEQ proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenOutput {
    /// Public spend key contribution.
    pub pubkey: [u8; 32],
    /// DLEQ proof for `pubkey`.
    pub proof: DleqProof,
}

/// Derived joint addresses and swap id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointAddresses {
    /// Joint Monero stagenet address.
    pub xmr_address: String,
    /// Joint Wownero address.
    pub wow_address: String,
    /// `Keccak256(alice_pub || bob_pub)`.
    pub swap_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRefundArtifact {
    pub metadata: RefundArtifactMetadata,
    pub tx_hash: TxHash,
    pub tx_bytes: Vec<u8>,
}

impl PersistedRefundArtifact {
    pub fn to_wallet_artifact(&self) -> RefundArtifact {
        RefundArtifact {
            metadata: self.metadata.clone(),
            tx_hash: self.tx_hash,
            tx_bytes: self.tx_bytes.clone(),
        }
    }

    pub fn validate_binding(
        &self,
        expected_chain: RefundChain,
        expected_lock_tx_hash: TxHash,
        expected_destination: &str,
        expected_refund_height: u64,
    ) -> Result<(), SwapError> {
        self.to_wallet_artifact()
            .validate_binding(
                expected_chain,
                expected_lock_tx_hash,
                expected_destination,
                expected_refund_height,
            )
            .map_err(|e| SwapError::InvalidRefundArtifact(e.to_string()))
    }
}

impl From<RefundArtifact> for PersistedRefundArtifact {
    fn from(value: RefundArtifact) -> Self {
        Self {
            metadata: value.metadata,
            tx_hash: value.tx_hash,
            tx_bytes: value.tx_bytes,
        }
    }
}

/// Persisted swap state.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SwapState {
    /// Phase 1: local key generation complete.
    KeyGeneration {
        role: SwapRole,
        params: SwapParams,
        /// This party's public contribution (safe to share).
        my_pubkey: [u8; 32],
        /// This party's DLEQ proof (safe to share).
        my_proof: DleqProof,
        /// Secret scalar ; NEVER serialized; stored separately.
        #[serde(skip)]
        secret_bytes: [u8; 32],
    },
    /// Phase 2: both pubkeys and proofs received; DLEQ verified.
    DleqExchange {
        role: SwapRole,
        params: SwapParams,
        my_pubkey: [u8; 32],
        counterparty_pubkey: [u8; 32],
        #[serde(skip)]
        secret_bytes: [u8; 32],
    },
    /// Phase 3: joint addresses derived.
    JointAddress {
        role: SwapRole,
        params: SwapParams,
        addresses: JointAddresses,
        my_pubkey: [u8; 32],
        counterparty_pubkey: [u8; 32],
        #[serde(default)]
        before_wow_lock_checkpoint: Option<RefundCheckpoint>,
        #[serde(skip)]
        secret_bytes: [u8; 32],
    },
    /// Alice verified the WOW lock and locked XMR.
    XmrLocked {
        role: SwapRole,
        params: SwapParams,
        addresses: JointAddresses,
        wow_lock_tx: [u8; 32],
        xmr_lock_tx: [u8; 32],
        my_pubkey: [u8; 32],
        counterparty_pubkey: [u8; 32],
        /// Local adaptor pre-signature.
        my_adaptor_pre_sig: AdaptorSignature,
        /// Counterparty pre-signature, if received.
        counterparty_pre_sig: Option<AdaptorSignature>,
        /// Counterparty pubkey used as the adaptor point.
        adaptor_point: [u8; 32],
        /// Stored XMR refund artifact.
        #[serde(default)]
        before_wow_lock_checkpoint: Option<RefundCheckpoint>,
        #[serde(default)]
        before_xmr_lock_checkpoint: Option<RefundCheckpoint>,
        #[serde(default)]
        refund_artifact: Option<PersistedRefundArtifact>,
        #[serde(skip)]
        secret_bytes: [u8; 32],
    },
    /// Bob locked WOW to the joint address.
    WowLocked {
        role: SwapRole,
        params: SwapParams,
        addresses: JointAddresses,
        wow_lock_tx: [u8; 32],
        my_pubkey: [u8; 32],
        counterparty_pubkey: [u8; 32],
        my_adaptor_pre_sig: AdaptorSignature,
        counterparty_pre_sig: Option<AdaptorSignature>,
        adaptor_point: [u8; 32],
        /// Stored WOW refund artifact.
        #[serde(default)]
        before_wow_lock_checkpoint: Option<RefundCheckpoint>,
        #[serde(default)]
        before_xmr_lock_checkpoint: Option<RefundCheckpoint>,
        #[serde(default)]
        refund_artifact: Option<PersistedRefundArtifact>,
        #[serde(skip)]
        secret_bytes: [u8; 32],
    },
    /// Claim complete.
    Complete {
        role: SwapRole,
        addresses: JointAddresses,
        /// Bob's revealed secret scalar.
        k_b_revealed: [u8; 32],
    },
    /// Refund complete.
    Refunded {
        role: SwapRole,
        addresses: JointAddresses,
        /// Refund transaction hash.
        refund_tx_hash: [u8; 32],
        #[serde(default)]
        refund_evidence: Option<RefundEvidence>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SwapError {
    #[error("DLEQ proof verification failed: {0}")]
    DleqFailed(String),
    #[error("invalid state transition from phase {0}")]
    InvalidTransition(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("invalid timelock: {0}")]
    InvalidTimelock(String),
    #[error("invalid refund artifact: {0}")]
    InvalidRefundArtifact(String),
    #[error("refund checkpoint blocked: {0}")]
    RefundCheckpointBlocked(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

impl SwapState {
    /// Generate the local key contribution.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(
        role: SwapRole,
        params: SwapParams,
        rng: &mut R,
    ) -> (Self, [u8; 32]) {
        let contrib = KeyContribution::generate(rng);
        let my_pubkey = contrib.public_bytes();
        let secret_bytes = contrib.secret.to_bytes();
        let my_proof = DleqProof::prove(&contrib.secret, &contrib.public, b"xmr-wow-swap-v1", rng);
        let state = SwapState::KeyGeneration {
            role,
            params,
            my_pubkey,
            my_proof,
            secret_bytes,
        };
        (state, secret_bytes)
    }

    /// Phase 2: Receive counterparty's pubkey + proof and verify.
    pub fn receive_counterparty_key(
        self,
        counterparty_pubkey: [u8; 32],
        counterparty_proof: &DleqProof,
    ) -> Result<SwapState, SwapError> {
        match self {
            SwapState::KeyGeneration {
                role,
                params,
                my_pubkey,
                secret_bytes,
                ..
            } => {
                // Decompress, validate on-curve, and reject torsion points
                let point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;

                counterparty_proof
                    .verify(&point, b"xmr-wow-swap-v1")
                    .map_err(|e| SwapError::DleqFailed(e.to_string()))?;

                Ok(SwapState::DleqExchange {
                    role,
                    params,
                    my_pubkey,
                    counterparty_pubkey,
                    secret_bytes,
                })
            }
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
    }

    /// Phase 3: Derive joint addresses from the two public keys.
    pub fn derive_joint_addresses(self) -> Result<SwapState, SwapError> {
        match self {
            SwapState::DleqExchange {
                role,
                params,
                my_pubkey,
                counterparty_pubkey,
                secret_bytes,
            } => {
                use curve25519_dalek::edwards::CompressedEdwardsY;
                use curve25519_dalek::scalar::Scalar;

                let my_point = CompressedEdwardsY::from_slice(&my_pubkey)
                    .map_err(|_| SwapError::Crypto("my point invalid".into()))?
                    .decompress()
                    .ok_or_else(|| SwapError::Crypto("my point decompress failed".into()))?;

                let their_point = CompressedEdwardsY::from_slice(&counterparty_pubkey)
                    .map_err(|_| SwapError::Crypto("their point invalid".into()))?
                    .decompress()
                    .ok_or_else(|| SwapError::Crypto("their point decompress failed".into()))?;

                // Joint spend key = my_key + their_key
                let joint_spend = combine_public_keys(&my_point, &their_point);

                // View key derived from joint spend key
                let joint_spend_scalar =
                    Scalar::from_bytes_mod_order(joint_spend.compress().to_bytes());
                let view_scalar = derive_view_key(&joint_spend_scalar);
                let view_point = view_scalar * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

                // Derive joint addresses for both chains
                let (alice_pub, bob_pub) = match role {
                    SwapRole::Alice => (my_point, their_point),
                    SwapRole::Bob => (their_point, my_point),
                };

                let xmr_address =
                    joint_address(&alice_pub, &bob_pub, &view_point, Network::MoneroStagenet);
                let wow_address =
                    joint_address(&alice_pub, &bob_pub, &view_point, Network::Wownero);

                // Swap ID = Keccak256(alice_pub_bytes || bob_pub_bytes)
                let mut id_input = Vec::with_capacity(64);
                id_input.extend_from_slice(&alice_pub.compress().to_bytes());
                id_input.extend_from_slice(&bob_pub.compress().to_bytes());
                let swap_id = keccak256(&id_input);

                let addresses = JointAddresses {
                    xmr_address,
                    wow_address,
                    swap_id,
                };

                Ok(SwapState::JointAddress {
                    role,
                    params,
                    addresses,
                    my_pubkey,
                    counterparty_pubkey,
                    before_wow_lock_checkpoint: None,
                    secret_bytes,
                })
            }
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
        .and_then(SwapState::refresh_refund_readiness)
    }

    /// Transition to XmrLocked after Alice locks XMR (second lock).
    ///
    /// Primary path: accepts WowLocked (Alice verifies Bob's WOW lock, then locks XMR).
    /// Fallback: accepts JointAddress (creates adaptor pre-sig, placeholder wow_lock_tx).
    pub fn record_xmr_lock(self, xmr_lock_tx: [u8; 32]) -> Result<SwapState, SwapError> {
        match self {
            SwapState::WowLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                secret_bytes,
                ..
            } => Ok(SwapState::XmrLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                xmr_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact: None,
                secret_bytes,
            }),
            SwapState::JointAddress {
                role,
                params,
                addresses,
                my_pubkey,
                counterparty_pubkey,
                before_wow_lock_checkpoint,
                secret_bytes,
            } => {
                let my_scalar =
                    curve25519_dalek::scalar::Scalar::from_canonical_bytes(secret_bytes)
                        .into_option()
                        .ok_or_else(|| SwapError::Crypto("invalid secret scalar".into()))?;
                let my_point = KeyContribution::from_public_bytes(&my_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;
                let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;

                // Create adaptor pre-sig: adapted by counterparty's pubkey
                let my_adaptor_pre_sig = AdaptorSignature::sign(
                    &my_scalar,
                    &my_point,
                    &addresses.swap_id,
                    &counterparty_point,
                    &mut rand::rngs::OsRng,
                );

                Ok(SwapState::XmrLocked {
                    role,
                    params,
                    addresses,
                    wow_lock_tx: [0u8; 32], // WOW lock tx not known yet (fallback path)
                    xmr_lock_tx,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig: None,
                    adaptor_point: counterparty_pubkey,
                    before_wow_lock_checkpoint,
                    before_xmr_lock_checkpoint: None,
                    refund_artifact: None,
                    secret_bytes,
                })
            }
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
        .and_then(SwapState::refresh_refund_readiness)
    }

    /// Transition to WowLocked after Bob locks WOW (first lock).
    ///
    /// Accepts JointAddress: Bob locks WOW first, creating an adaptor pre-sig.
    pub fn record_wow_lock(self, wow_lock_tx: [u8; 32]) -> Result<SwapState, SwapError> {
        match self {
            SwapState::JointAddress {
                role,
                params,
                addresses,
                my_pubkey,
                counterparty_pubkey,
                before_wow_lock_checkpoint,
                secret_bytes,
            } => {
                // Bob's first lock: create adaptor pre-sig
                let my_scalar =
                    curve25519_dalek::scalar::Scalar::from_canonical_bytes(secret_bytes)
                        .into_option()
                        .ok_or_else(|| SwapError::Crypto("invalid secret scalar".into()))?;
                let my_point = KeyContribution::from_public_bytes(&my_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;
                let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;

                let my_adaptor_pre_sig = AdaptorSignature::sign(
                    &my_scalar,
                    &my_point,
                    &addresses.swap_id,
                    &counterparty_point,
                    &mut rand::rngs::OsRng,
                );

                Ok(SwapState::WowLocked {
                    role,
                    params,
                    addresses,
                    wow_lock_tx,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig: None,
                    adaptor_point: counterparty_pubkey,
                    before_wow_lock_checkpoint,
                    before_xmr_lock_checkpoint: None,
                    refund_artifact: None,
                    secret_bytes,
                })
            }
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
        .and_then(SwapState::refresh_refund_readiness)
    }

    /// Store the counterparty's adaptor pre-signature (received via exchange-pre-sig).
    ///
    /// Validates the pre-sig using verify_pre_sig: the counterparty's pre-sig
    /// is adapted by MY pubkey (since I'm the one who will extract the secret).
    pub fn receive_counterparty_pre_sig(
        self,
        pre_sig: AdaptorSignature,
    ) -> Result<SwapState, SwapError> {
        match self {
            SwapState::XmrLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                xmr_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact,
                secret_bytes,
                ..
            } => {
                // Counterparty's pre-sig is adapted by MY pubkey
                let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;
                let my_point = KeyContribution::from_public_bytes(&my_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;

                pre_sig
                    .verify_pre_sig(&counterparty_point, &addresses.swap_id, &my_point)
                    .map_err(|e| {
                        SwapError::Crypto(format!(
                            "counterparty pre-sig verification failed: {}",
                            e
                        ))
                    })?;

                Ok(SwapState::XmrLocked {
                    role,
                    params,
                    addresses,
                    wow_lock_tx,
                    xmr_lock_tx,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig: Some(pre_sig),
                    adaptor_point,
                    before_wow_lock_checkpoint,
                    before_xmr_lock_checkpoint,
                    refund_artifact,
                    secret_bytes,
                })
            }
            SwapState::WowLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact,
                secret_bytes,
                ..
            } => {
                let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;
                let my_point = KeyContribution::from_public_bytes(&my_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;

                pre_sig
                    .verify_pre_sig(&counterparty_point, &addresses.swap_id, &my_point)
                    .map_err(|e| {
                        SwapError::Crypto(format!(
                            "counterparty pre-sig verification failed: {}",
                            e
                        ))
                    })?;

                Ok(SwapState::WowLocked {
                    role,
                    params,
                    addresses,
                    wow_lock_tx,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig: Some(pre_sig),
                    adaptor_point,
                    before_wow_lock_checkpoint,
                    before_xmr_lock_checkpoint,
                    refund_artifact,
                    secret_bytes,
                })
            }
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
        .and_then(SwapState::refresh_refund_readiness)
    }

    /// Complete the claim: extract counterparty's secret from their completed adaptor sig.
    ///
    /// Returns (new_state, counterparty_secret_scalar).
    ///
    /// ADAPTOR SIG ATOMICITY: The secret is extracted via `pre_sig.extract_secret(completed)`,
    /// NOT via a RevealSecret message. This is the core atomic property of the protocol.
    pub fn complete_with_adaptor_claim(
        self,
        counterparty_completed_sig: &CompletedSignature,
    ) -> Result<(SwapState, curve25519_dalek::scalar::Scalar), SwapError> {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;

        match self {
            SwapState::WowLocked {
                role,
                addresses,
                counterparty_pubkey,
                counterparty_pre_sig: Some(pre_sig),
                ..
            } => {
                // Extract the counterparty's secret scalar
                let extracted_scalar = pre_sig
                    .extract_secret(counterparty_completed_sig)
                    .map_err(|e| SwapError::Crypto(format!("secret extraction failed: {}", e)))?;

                // Verify: extracted_scalar * G == counterparty_pubkey
                let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;
                let computed_point = extracted_scalar * G;
                if computed_point.compress() != counterparty_point.compress() {
                    return Err(SwapError::Crypto(
                        "extracted secret does not match counterparty pubkey".into(),
                    ));
                }

                let k_b_revealed = extracted_scalar.to_bytes();
                Ok((
                    SwapState::Complete {
                        role,
                        addresses,
                        k_b_revealed,
                    },
                    extracted_scalar,
                ))
            }
            // Alice may be in XmrLocked if she received Bob's pre-sig but never
            // verified his WOW lock (same extraction logic applies)
            SwapState::XmrLocked {
                role,
                addresses,
                counterparty_pubkey,
                counterparty_pre_sig: Some(pre_sig),
                ..
            } => {
                let extracted_scalar = pre_sig
                    .extract_secret(counterparty_completed_sig)
                    .map_err(|e| SwapError::Crypto(format!("secret extraction failed: {}", e)))?;

                let counterparty_point = KeyContribution::from_public_bytes(&counterparty_pubkey)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;
                let computed_point = extracted_scalar * G;
                if computed_point.compress() != counterparty_point.compress() {
                    return Err(SwapError::Crypto(
                        "extracted secret does not match counterparty pubkey".into(),
                    ));
                }

                let k_b_revealed = extracted_scalar.to_bytes();
                Ok((
                    SwapState::Complete {
                        role,
                        addresses,
                        k_b_revealed,
                    },
                    extracted_scalar,
                ))
            }
            SwapState::WowLocked {
                counterparty_pre_sig: None,
                ..
            }
            | SwapState::XmrLocked {
                counterparty_pre_sig: None,
                ..
            } => Err(SwapError::InvalidTransition(
                "cannot claim without counterparty's pre-sig (run exchange-pre-sig first)".into(),
            )),
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
    }

    /// Compute the joint spend point and view scalar from two pubkeys.
    ///
    /// Returns (joint_spend_point, view_scalar) for use with wallet operations.
    pub fn compute_joint_keys(
        my_pubkey: &[u8; 32],
        counterparty_pubkey: &[u8; 32],
        role: SwapRole,
    ) -> Result<
        (
            curve25519_dalek::edwards::EdwardsPoint,
            curve25519_dalek::scalar::Scalar,
        ),
        SwapError,
    > {
        let my_point = KeyContribution::from_public_bytes(my_pubkey)
            .map_err(|e| SwapError::Crypto(e.to_string()))?;
        let their_point = KeyContribution::from_public_bytes(counterparty_pubkey)
            .map_err(|e| SwapError::Crypto(e.to_string()))?;

        let (alice_pub, bob_pub) = match role {
            SwapRole::Alice => (my_point, their_point),
            SwapRole::Bob => (their_point, my_point),
        };

        let joint_spend = combine_public_keys(&alice_pub, &bob_pub);
        let joint_spend_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
            joint_spend.compress().to_bytes(),
        );
        let view_scalar = derive_view_key(&joint_spend_scalar);

        Ok((joint_spend, view_scalar))
    }

    fn checkpoint_status(decision_status: GuaranteeStatus) -> RefundCheckpointStatus {
        match decision_status {
            GuaranteeStatus::Supported => RefundCheckpointStatus::Ready,
            GuaranteeStatus::Blocked => RefundCheckpointStatus::Blocked,
            GuaranteeStatus::UnsupportedForGuarantee => {
                RefundCheckpointStatus::UnsupportedForGuarantee
            }
        }
    }

    fn checkpoint_from_mode(
        name: RefundCheckpointName,
        chain: RefundChain,
        refund_address: Option<String>,
        refund_height: u64,
        artifact_present: bool,
        artifact_validated: bool,
        mode: GuaranteeMode,
    ) -> RefundCheckpoint {
        if refund_address.is_none() {
            return RefundCheckpoint {
                name,
                chain,
                status: RefundCheckpointStatus::Blocked,
                reason: "refund destination missing from transcript".into(),
                artifact_present,
                artifact_validated,
                refund_address,
                refund_height,
            };
        }

        let decision = guarantee_decision(mode);
        let (status, reason) = if artifact_validated {
            (
                Self::checkpoint_status(decision.status),
                if decision.status == GuaranteeStatus::Supported {
                    format!("validated refund artifact recorded for {}", name.display())
                } else {
                    decision.reason.to_string()
                },
            )
        } else if decision.status == GuaranteeStatus::Supported {
            let reason = if artifact_present {
                format!(
                    "stored refund artifact failed validation for {}",
                    name.display()
                )
            } else {
                format!(
                    "validated refund artifact not yet recorded for {}",
                    name.display()
                )
            };
            (RefundCheckpointStatus::Blocked, reason)
        } else {
            (Self::checkpoint_status(decision.status), decision.reason.to_string())
        };

        RefundCheckpoint {
            name,
            chain,
            status,
            reason,
            artifact_present,
            artifact_validated,
            refund_address,
            refund_height,
        }
    }

    fn build_before_wow_lock_checkpoint(
        params: &SwapParams,
        artifact_present: bool,
        artifact_validated: bool,
    ) -> RefundCheckpoint {
        Self::checkpoint_from_mode(
            RefundCheckpointName::BeforeWowLock,
            RefundChain::Wow,
            params.bob_refund_address.clone(),
            params.wow_refund_height,
            artifact_present,
            artifact_validated,
            GuaranteeMode::CurrentSingleSignerPreLockArtifact,
        )
    }

    fn build_before_xmr_lock_checkpoint(
        params: &SwapParams,
        artifact_present: bool,
        artifact_validated: bool,
    ) -> RefundCheckpoint {
        Self::checkpoint_from_mode(
            RefundCheckpointName::BeforeXmrLock,
            RefundChain::Xmr,
            params.alice_refund_address.clone(),
            params.xmr_refund_height,
            artifact_present,
            artifact_validated,
            GuaranteeMode::LiveXmrUnlockTimeRefund,
        )
    }

    /// Transition to Complete after a valid counterparty secret is observed on-chain.
    ///
    /// Verifies that `k_b_revealed * G == adaptor_point` before accepting the
    /// transition. This ensures the revealed scalar is genuinely the discrete
    /// log of the adaptor point used in the pre-signature.
    pub fn complete_with_claim(self, k_b_revealed: [u8; 32]) -> Result<SwapState, SwapError> {
        match self {
            SwapState::XmrLocked {
                role,
                addresses,
                adaptor_point,
                ..
            }
            | SwapState::WowLocked {
                role,
                addresses,
                adaptor_point,
                ..
            } => {
                // Verify: k_b_revealed * G == adaptor point used in the lock state.
                use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
                use curve25519_dalek::scalar::Scalar;

                let k_b_scalar = Scalar::from_canonical_bytes(k_b_revealed)
                    .into_option()
                    .ok_or_else(|| SwapError::Crypto("invalid k_b scalar".into()))?;
                let computed_point = k_b_scalar * G;

                let expected_point = KeyContribution::from_public_bytes(&adaptor_point)
                    .map_err(|e| SwapError::Crypto(e.to_string()))?;

                if computed_point.compress() != expected_point.compress() {
                    return Err(SwapError::Crypto(
                        "k_b_revealed does not match adaptor point".into(),
                    ));
                }

                Ok(SwapState::Complete {
                    role,
                    addresses,
                    k_b_revealed,
                })
            }
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
    }

    /// Transition to Refunded after timelock expiry.
    ///
    /// Valid from XmrLocked or WowLocked states.
    pub fn complete_with_refund(self, refund_tx_hash: [u8; 32]) -> Result<SwapState, SwapError> {
        match self {
            SwapState::XmrLocked {
                role, addresses, ..
            } => Ok(SwapState::Refunded {
                role,
                addresses,
                refund_tx_hash,
                refund_evidence: Some(RefundEvidence {
                    chain: RefundChain::Xmr,
                    refund_tx_hash,
                    confirmed_height: None,
                }),
            }),
            SwapState::WowLocked {
                role, addresses, ..
            } => Ok(SwapState::Refunded {
                role,
                addresses,
                refund_tx_hash,
                refund_evidence: Some(RefundEvidence {
                    chain: RefundChain::Wow,
                    refund_tx_hash,
                    confirmed_height: None,
                }),
            }),
            other => Err(SwapError::InvalidTransition(format!(
                "{:?}",
                std::mem::discriminant(&other)
            ))),
        }
    }

    fn expected_refund_binding_owned(
        &self,
    ) -> Result<(RefundChain, TxHash, String, u64), SwapError> {
        match self {
            SwapState::XmrLocked {
                params,
                xmr_lock_tx,
                ..
            } => {
                let destination = params.alice_refund_address.clone().ok_or_else(|| {
                    SwapError::InvalidRefundArtifact(
                        "alice_refund_address missing for XMR refund artifact".into(),
                    )
                })?;
                Ok((
                    RefundChain::Xmr,
                    *xmr_lock_tx,
                    destination,
                    params.xmr_refund_height,
                ))
            }
            SwapState::WowLocked {
                params,
                wow_lock_tx,
                ..
            } => {
                let destination = params.bob_refund_address.clone().ok_or_else(|| {
                    SwapError::InvalidRefundArtifact(
                        "bob_refund_address missing for WOW refund artifact".into(),
                    )
                })?;
                Ok((
                    RefundChain::Wow,
                    *wow_lock_tx,
                    destination,
                    params.wow_refund_height,
                ))
            }
            _ => Err(SwapError::InvalidTransition(
                "refund artifacts only apply to locked swap states".into(),
            )),
        }
    }

    pub fn refund_artifact(&self) -> Option<&PersistedRefundArtifact> {
        match self {
            SwapState::XmrLocked { refund_artifact, .. }
            | SwapState::WowLocked { refund_artifact, .. } => refund_artifact.as_ref(),
            _ => None,
        }
    }

    pub fn require_refund_artifact(&self) -> Result<&PersistedRefundArtifact, SwapError> {
        self.refund_artifact().ok_or_else(|| {
            SwapError::InvalidRefundArtifact(
                "refund artifact missing for locked state".into(),
            )
        })
    }

    pub fn validate_refund_artifact(&self) -> Result<(), SwapError> {
        let artifact = self.require_refund_artifact()?;
        let (chain, lock_tx_hash, destination, refund_height) =
            self.expected_refund_binding_owned()?;
        artifact.validate_binding(chain, lock_tx_hash, &destination, refund_height)
    }

    pub fn record_refund_artifact(
        self,
        artifact: PersistedRefundArtifact,
    ) -> Result<SwapState, SwapError> {
        let (chain, lock_tx_hash, destination, refund_height) =
            self.expected_refund_binding_owned()?;
        artifact.validate_binding(chain, lock_tx_hash, &destination, refund_height)?;

        match self {
            SwapState::XmrLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                xmr_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                secret_bytes,
                ..
            } => Ok(SwapState::XmrLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                xmr_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact: Some(artifact),
                secret_bytes,
            }),
            SwapState::WowLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                secret_bytes,
                ..
            } => Ok(SwapState::WowLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact: Some(artifact),
                secret_bytes,
            }),
            _ => Err(SwapError::InvalidTransition(
                "refund artifacts only apply to locked swap states".into(),
            )),
        }
        .and_then(SwapState::refresh_refund_readiness)
    }

    pub fn refresh_refund_readiness(self) -> Result<SwapState, SwapError> {
        match self {
            SwapState::JointAddress {
                role,
                params,
                addresses,
                my_pubkey,
                counterparty_pubkey,
                secret_bytes,
                ..
            } => Ok(SwapState::JointAddress {
                role,
                params: params.clone(),
                addresses,
                my_pubkey,
                counterparty_pubkey,
                before_wow_lock_checkpoint: Some(Self::build_before_wow_lock_checkpoint(
                    &params, false, false,
                )),
                secret_bytes,
            }),
            SwapState::WowLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                refund_artifact,
                secret_bytes,
                ..
            } => {
                let artifact_present = refund_artifact.is_some();
                let artifact_validated = refund_artifact
                    .as_ref()
                    .map(|_| {
                        refund_artifact
                            .as_ref()
                            .map(|_| ())
                            .is_some()
                    })
                    .unwrap_or(false)
                    && Self::WowLocked {
                        role,
                        params: params.clone(),
                        addresses: addresses.clone(),
                        wow_lock_tx,
                        my_pubkey,
                        counterparty_pubkey,
                        my_adaptor_pre_sig: my_adaptor_pre_sig.clone(),
                        counterparty_pre_sig: counterparty_pre_sig.clone(),
                        adaptor_point,
                        before_wow_lock_checkpoint: None,
                        before_xmr_lock_checkpoint: None,
                        refund_artifact: refund_artifact.clone(),
                        secret_bytes,
                    }
                    .validate_refund_artifact()
                    .is_ok();

                Ok(SwapState::WowLocked {
                    role,
                    params: params.clone(),
                    addresses,
                    wow_lock_tx,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig,
                    adaptor_point,
                    before_wow_lock_checkpoint: Some(Self::build_before_wow_lock_checkpoint(
                        &params,
                        artifact_present,
                        artifact_validated,
                    )),
                    before_xmr_lock_checkpoint: Some(Self::build_before_xmr_lock_checkpoint(
                        &params, false, false,
                    )),
                    refund_artifact,
                    secret_bytes,
                })
            }
            SwapState::XmrLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                xmr_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                refund_artifact,
                secret_bytes,
                ..
            } => {
                let artifact_present = refund_artifact.is_some();
                let artifact_validated = artifact_present
                    && Self::XmrLocked {
                        role,
                        params: params.clone(),
                        addresses: addresses.clone(),
                        wow_lock_tx,
                        xmr_lock_tx,
                        my_pubkey,
                        counterparty_pubkey,
                        my_adaptor_pre_sig: my_adaptor_pre_sig.clone(),
                        counterparty_pre_sig: counterparty_pre_sig.clone(),
                        adaptor_point,
                        before_wow_lock_checkpoint: before_wow_lock_checkpoint.clone(),
                        before_xmr_lock_checkpoint: None,
                        refund_artifact: refund_artifact.clone(),
                        secret_bytes,
                    }
                    .validate_refund_artifact()
                    .is_ok();

                Ok(SwapState::XmrLocked {
                    role,
                    params: params.clone(),
                    addresses,
                    wow_lock_tx,
                    xmr_lock_tx,
                    my_pubkey,
                    counterparty_pubkey,
                    my_adaptor_pre_sig,
                    counterparty_pre_sig,
                    adaptor_point,
                    before_wow_lock_checkpoint: before_wow_lock_checkpoint.or_else(|| {
                        Some(Self::build_before_wow_lock_checkpoint(&params, false, false))
                    }),
                    before_xmr_lock_checkpoint: Some(Self::build_before_xmr_lock_checkpoint(
                        &params,
                        artifact_present,
                        artifact_validated,
                    )),
                    refund_artifact,
                    secret_bytes,
                })
            }
            other => Ok(other),
        }
    }

    pub fn before_wow_lock_checkpoint(&self) -> Option<&RefundCheckpoint> {
        match self {
            SwapState::JointAddress {
                before_wow_lock_checkpoint,
                ..
            }
            | SwapState::WowLocked {
                before_wow_lock_checkpoint,
                ..
            }
            | SwapState::XmrLocked {
                before_wow_lock_checkpoint,
                ..
            } => before_wow_lock_checkpoint.as_ref(),
            _ => None,
        }
    }

    pub fn before_xmr_lock_checkpoint(&self) -> Option<&RefundCheckpoint> {
        match self {
            SwapState::WowLocked {
                before_xmr_lock_checkpoint,
                ..
            }
            | SwapState::XmrLocked {
                before_xmr_lock_checkpoint,
                ..
            } => before_xmr_lock_checkpoint.as_ref(),
            _ => None,
        }
    }

    pub fn checkpoint(&self, name: RefundCheckpointName) -> Option<&RefundCheckpoint> {
        match name {
            RefundCheckpointName::BeforeWowLock => self.before_wow_lock_checkpoint(),
            RefundCheckpointName::BeforeXmrLock => self.before_xmr_lock_checkpoint(),
        }
    }

    pub fn require_checkpoint_ready(
        &self,
        name: RefundCheckpointName,
    ) -> Result<(), SwapError> {
        let checkpoint = self.checkpoint(name).ok_or_else(|| {
            SwapError::RefundCheckpointBlocked(format!(
                "{} checkpoint missing from persisted state",
                name.display()
            ))
        })?;

        if checkpoint.status != RefundCheckpointStatus::Ready {
            return Err(SwapError::RefundCheckpointBlocked(format!(
                "{} is {}. {}",
                checkpoint.name.display(),
                checkpoint.status.label(),
                checkpoint.reason
            )));
        }

        if !checkpoint.artifact_validated {
            return Err(SwapError::RefundCheckpointBlocked(format!(
                "{} is not ready. validated refund artifact missing.",
                checkpoint.name.display()
            )));
        }

        Ok(())
    }

    pub fn next_safe_action(&self) -> String {
        let swap_id = self
            .swap_id()
            .map(hex::encode)
            .unwrap_or_else(|| "<pending>".into());
        match self {
            SwapState::KeyGeneration { role, .. } => match role {
                SwapRole::Alice => {
                    "Send the init message to Bob and wait for his response, then run import."
                        .into()
                }
                SwapRole::Bob => "Send the response message to Alice.".into(),
            },
            SwapState::DleqExchange { role, .. } => match role {
                SwapRole::Alice => "Run import with Bob's response message.".into(),
                SwapRole::Bob => "Run import with Alice's init message.".into(),
            },
            SwapState::JointAddress { role, .. } => {
                let checkpoint = self.before_wow_lock_checkpoint();
                match role {
                    SwapRole::Alice => match checkpoint {
                        Some(cp) if cp.status == RefundCheckpointStatus::Ready => {
                            "Wait for Bob to run lock-wow.".into()
                        }
                        Some(cp) => format!(
                            "Wait. Bob's {} checkpoint is {}. {}",
                            cp.name.display(),
                            cp.status.label(),
                            cp.reason
                        ),
                        None => "Refund checkpoint missing; do not proceed with WOW lock.".into(),
                    },
                    SwapRole::Bob => match checkpoint {
                        Some(cp) if cp.status == RefundCheckpointStatus::Ready => {
                            format!("Run lock-wow --swap-id {} to lock WOW first.", swap_id)
                        }
                        Some(cp) => format!(
                            "Do not run lock-wow. {} is {}. {}",
                            cp.name.display(),
                            cp.status.label(),
                            cp.reason
                        ),
                        None => "Refund checkpoint missing; do not proceed with WOW lock.".into(),
                    },
                }
            }
            SwapState::WowLocked {
                role,
                counterparty_pre_sig,
                ..
            } => {
                let checkpoint = self.before_xmr_lock_checkpoint();
                match role {
                    SwapRole::Alice => match checkpoint {
                        Some(cp) if cp.status == RefundCheckpointStatus::Ready => {
                            format!("Run lock-xmr --swap-id {} after verifying WOW.", swap_id)
                        }
                        Some(cp) => format!(
                            "Do not run lock-xmr. {} is {}. {}",
                            cp.name.display(),
                            cp.status.label(),
                            cp.reason
                        ),
                        None => "Refund checkpoint missing; do not proceed with XMR lock.".into(),
                    },
                    SwapRole::Bob => match checkpoint {
                        Some(cp) if cp.status != RefundCheckpointStatus::Ready => format!(
                            "Wait. Alice's {} checkpoint is {}. {}",
                            cp.name.display(),
                            cp.status.label(),
                            cp.reason
                        ),
                        _ if counterparty_pre_sig.is_none() => {
                            "Run exchange-pre-sig to import counterparty's adaptor pre-signature."
                                .into()
                        }
                        _ => "Run claim-xmr to send your claim proof and claim XMR.".into(),
                    },
                }
            }
            SwapState::XmrLocked {
                role,
                counterparty_pre_sig,
                ..
            } => match role {
                SwapRole::Alice => {
                    if counterparty_pre_sig.is_none() {
                        "Send your pre-sig to Bob and run exchange-pre-sig with Bob's pre-sig."
                            .into()
                    } else {
                        "Wait for Bob's claim proof, then run claim-wow.".into()
                    }
                }
                SwapRole::Bob => {
                    if counterparty_pre_sig.is_none() {
                        "Run exchange-pre-sig to import counterparty's adaptor pre-signature."
                            .into()
                    } else {
                        "Run claim-xmr to send your claim proof and claim XMR.".into()
                    }
                }
            },
            SwapState::Complete { .. } => {
                "Swap completed successfully. No further action needed.".into()
            }
            SwapState::Refunded { .. } => {
                "Refund recorded. No further action needed.".into()
            }
        }
    }

    /// The swap ID if available.
    pub fn swap_id(&self) -> Option<[u8; 32]> {
        match self {
            SwapState::JointAddress { addresses, .. } => Some(addresses.swap_id),
            SwapState::XmrLocked { addresses, .. } => Some(addresses.swap_id),
            SwapState::WowLocked { addresses, .. } => Some(addresses.swap_id),
            SwapState::Complete { addresses, .. } => Some(addresses.swap_id),
            SwapState::Refunded { addresses, .. } => Some(addresses.swap_id),
            _ => None,
        }
    }
}

/// Restore a decrypted secret scalar into a deserialized SwapState.
///
/// Because `secret_bytes` is `#[serde(skip)]`, deserializing SwapState from
/// JSON zeros the secret field. This function reconstructs the state with
/// the decrypted secret injected. Needed when loading state from SQLite.
///
/// Validates that `secret * G == my_pubkey` before accepting the secret.
pub fn restore_secret_into_state(
    state: SwapState,
    secret: [u8; 32],
) -> Result<SwapState, SwapError> {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
    use curve25519_dalek::scalar::Scalar;

    // Verify the secret matches the public key
    let scalar = Scalar::from_canonical_bytes(secret)
        .into_option()
        .ok_or_else(|| SwapError::Crypto("invalid secret scalar bytes".into()))?;

    match state {
        SwapState::KeyGeneration {
            role,
            params,
            my_pubkey,
            my_proof,
            ..
        } => {
            let computed = (scalar * G).compress().to_bytes();
            if computed != my_pubkey {
                return Err(SwapError::Crypto("secret does not match public key".into()));
            }
            Ok(SwapState::KeyGeneration {
                role,
                params,
                my_pubkey,
                my_proof,
                secret_bytes: secret,
            })
        }
        SwapState::DleqExchange {
            role,
            params,
            my_pubkey,
            counterparty_pubkey,
            ..
        } => {
            let computed = (scalar * G).compress().to_bytes();
            if computed != my_pubkey {
                return Err(SwapError::Crypto("secret does not match public key".into()));
            }
            Ok(SwapState::DleqExchange {
                role,
                params,
                my_pubkey,
                counterparty_pubkey,
                secret_bytes: secret,
            })
        }
        SwapState::JointAddress {
            role,
            params,
            addresses,
            my_pubkey,
            counterparty_pubkey,
            before_wow_lock_checkpoint,
            ..
        } => {
            let computed = (scalar * G).compress().to_bytes();
            if computed != my_pubkey {
                return Err(SwapError::Crypto("secret does not match public key".into()));
            }
            Ok(SwapState::JointAddress {
                role,
                params,
                addresses,
                my_pubkey,
                counterparty_pubkey,
                before_wow_lock_checkpoint,
                secret_bytes: secret,
            })
        }
        SwapState::XmrLocked {
            role,
            params,
            addresses,
            wow_lock_tx,
            xmr_lock_tx,
            my_pubkey,
            counterparty_pubkey,
            my_adaptor_pre_sig,
            counterparty_pre_sig,
            adaptor_point,
            before_wow_lock_checkpoint,
            before_xmr_lock_checkpoint,
            refund_artifact,
            ..
        } => {
            let computed = (scalar * G).compress().to_bytes();
            if computed != my_pubkey {
                return Err(SwapError::Crypto("secret does not match public key".into()));
            }
            Ok(SwapState::XmrLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                xmr_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact,
                secret_bytes: secret,
            })
        }
        SwapState::WowLocked {
            role,
            params,
            addresses,
            wow_lock_tx,
            my_pubkey,
            counterparty_pubkey,
            my_adaptor_pre_sig,
            counterparty_pre_sig,
            adaptor_point,
            before_wow_lock_checkpoint,
            before_xmr_lock_checkpoint,
            refund_artifact,
            ..
        } => {
            let computed = (scalar * G).compress().to_bytes();
            if computed != my_pubkey {
                return Err(SwapError::Crypto("secret does not match public key".into()));
            }
            Ok(SwapState::WowLocked {
                role,
                params,
                addresses,
                wow_lock_tx,
                my_pubkey,
                counterparty_pubkey,
                my_adaptor_pre_sig,
                counterparty_pre_sig,
                adaptor_point,
                before_wow_lock_checkpoint,
                before_xmr_lock_checkpoint,
                refund_artifact,
                secret_bytes: secret,
            })
        }
        // Complete and Refunded don't have secret_bytes
        SwapState::Complete { .. } | SwapState::Refunded { .. } => Err(
            SwapError::InvalidTransition("cannot restore secret into terminal state".into()),
        ),
    }
    .and_then(SwapState::refresh_refund_readiness)
}

// Need curve25519_dalek in scope
use curve25519_dalek;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sample_refund_timing() -> RefundTimingObservation {
        RefundTimingObservation {
            xmr_base_height: 100,
            wow_base_height: 200,
            xmr_lock_blocks: 500,
            wow_lock_blocks: 800,
            source: RefundTimingSource::DaemonHeightQuery,
        }
    }

    fn sample_params() -> SwapParams {
        let refund_timing = sample_refund_timing();
        let (_, xmr_refund_height, wow_refund_height) = build_observed_refund_timing(
            refund_timing.xmr_base_height,
            refund_timing.wow_base_height,
            refund_timing.xmr_lock_blocks,
            refund_timing.wow_lock_blocks,
        )
        .unwrap();

        SwapParams {
            amount_xmr: 1_000_000_000_000,
            amount_wow: 500_000_000_000_000,
            xmr_refund_height,
            wow_refund_height,
            refund_timing: Some(refund_timing),
            alice_refund_address: None,
            bob_refund_address: None,
        }
    }

    fn make_alice_bob() -> (SwapState, [u8; 32], SwapState, [u8; 32]) {
        let params = sample_params();
        let (alice, alice_secret) =
            SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
        let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
        (alice, alice_secret, bob, bob_secret)
    }

    fn get_pubkey_and_proof(state: &SwapState) -> ([u8; 32], DleqProof) {
        match state {
            SwapState::KeyGeneration {
                my_pubkey,
                my_proof,
                ..
            } => (*my_pubkey, my_proof.clone()),
            _ => panic!("wrong state"),
        }
    }

    #[test]
    fn key_generation_phase() {
        let mut params = sample_params();
        params.amount_xmr = 1_000;
        params.amount_wow = 500;
        let (state, _secret) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);
        match &state {
            SwapState::KeyGeneration {
                role, my_pubkey, ..
            } => {
                assert_eq!(*role, SwapRole::Alice);
                assert_ne!(*my_pubkey, [0u8; 32]);
            }
            _ => panic!("wrong state"),
        }
    }

    #[test]
    fn dleq_exchange_phase() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice2 = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();
        assert!(matches!(alice2, SwapState::DleqExchange { .. }));
    }

    #[test]
    fn wrong_dleq_proof_rejected() {
        let (alice, _, bob, _) = make_alice_bob();
        let mut params2 = sample_params();
        params2.amount_xmr = 1_000;
        params2.amount_wow = 500;
        // Make a proof for a DIFFERENT key
        let (charlie, _) = SwapState::generate(SwapRole::Bob, params2, &mut OsRng);
        let (bob_pub, _) = get_pubkey_and_proof(&bob);
        let (_, charlie_proof) = get_pubkey_and_proof(&charlie);
        // bob_pub + charlie_proof (mismatched) => should fail
        let result = alice.receive_counterparty_key(bob_pub, &charlie_proof);
        assert!(result.is_err());
    }

    #[test]
    fn joint_address_phase() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice2 = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();
        let alice3 = alice2.derive_joint_addresses().unwrap();
        match &alice3 {
            SwapState::JointAddress { addresses, .. } => {
                assert_eq!(addresses.xmr_address.len(), 95);
                assert_eq!(addresses.wow_address.len(), 97);
            }
            _ => panic!("wrong state"),
        }
    }

    #[test]
    fn both_parties_derive_same_joint_address() {
        let (alice, _, bob, _) = make_alice_bob();
        let (alice_pub, alice_proof) = get_pubkey_and_proof(&alice);
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);

        // Alice side
        let alice2 = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();
        let alice3 = alice2.derive_joint_addresses().unwrap();
        let alice_addr = match &alice3 {
            SwapState::JointAddress { addresses, .. } => addresses.xmr_address.clone(),
            _ => panic!("expected JointAddress for Alice after derive_joint_addresses"),
        };

        // Bob side
        let bob2 = bob
            .receive_counterparty_key(alice_pub, &alice_proof)
            .unwrap();
        let bob3 = bob2.derive_joint_addresses().unwrap();
        let bob_addr = match &bob3 {
            SwapState::JointAddress { addresses, .. } => addresses.xmr_address.clone(),
            _ => panic!("expected JointAddress for Bob after derive_joint_addresses"),
        };

        assert_eq!(
            alice_addr, bob_addr,
            "both parties must derive the same XMR address"
        );
    }

    #[test]
    fn both_parties_derive_same_wow_address() {
        let (alice, _, bob, _) = make_alice_bob();
        let (alice_pub, alice_proof) = get_pubkey_and_proof(&alice);
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);

        let alice3 = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();
        let bob3 = bob
            .receive_counterparty_key(alice_pub, &alice_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();

        let alice_wow = match &alice3 {
            SwapState::JointAddress { addresses, .. } => addresses.wow_address.clone(),
            _ => panic!("expected JointAddress for Alice WOW address check"),
        };
        let bob_wow = match &bob3 {
            SwapState::JointAddress { addresses, .. } => addresses.wow_address.clone(),
            _ => panic!("expected JointAddress for Bob WOW address check"),
        };
        assert_eq!(alice_wow, bob_wow);
        assert_eq!(alice_wow.len(), 97, "WOW address must be 97 chars");
    }

    #[test]
    fn xmr_lock_records_counterparty_adaptor_point() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice_locked = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();
        let xmr_lock_tx = [0xAAu8; 32];
        let locked = alice_locked.record_xmr_lock(xmr_lock_tx).unwrap();
        match locked {
            SwapState::XmrLocked {
                xmr_lock_tx: recorded,
                wow_lock_tx,
                adaptor_point,
                my_adaptor_pre_sig,
                ..
            } => {
                assert_eq!(recorded, xmr_lock_tx);
                assert_eq!(
                    wow_lock_tx, [0u8; 32],
                    "fallback wow lock placeholder is zeroed"
                );
                assert_eq!(adaptor_point, bob_pub, "Alice adapts against Bob's pubkey");
                assert_ne!(
                    my_adaptor_pre_sig.r_plus_t, [0u8; 32],
                    "pre-sig R_T must not be zero"
                );
                assert_ne!(
                    my_adaptor_pre_sig.s_prime, [0u8; 32],
                    "pre-sig s' must not be zero"
                );
            }
            _ => panic!("expected XmrLocked after Alice records the XMR lock"),
        }
    }

    #[test]
    fn torsion_point_rejected_by_receive_counterparty_key() {
        let (alice, _, bob, _) = make_alice_bob();
        let (_, bob_proof) = get_pubkey_and_proof(&bob);
        // Known small-order (order-8) point on Ed25519:
        // c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
        // This decompresses successfully but is NOT in the prime-order subgroup.
        let torsion_point: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0xfa,
        ];
        // Torsion check happens inside from_public_bytes, before DLEQ verify
        let result = alice.receive_counterparty_key(torsion_point, &bob_proof);
        assert!(result.is_err(), "torsion point must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("torsion") || err_msg.contains("prime"),
            "error should mention torsion/prime-order, got: {err_msg}"
        );
    }

    #[test]
    fn valid_point_accepted_by_receive_counterparty_key() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let result = alice.receive_counterparty_key(bob_pub, &bob_proof);
        assert!(result.is_ok(), "valid point must be accepted");
    }

    #[test]
    fn wow_lock_records_counterparty_adaptor_point() {
        let (alice, alice_secret, bob, _) = make_alice_bob();
        let (alice_pub, alice_proof) = get_pubkey_and_proof(&alice);
        let bob_locked = bob
            .receive_counterparty_key(alice_pub, &alice_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();
        let wow_lock_tx = [0xBBu8; 32];
        let locked = bob_locked.record_wow_lock(wow_lock_tx).unwrap();
        match &locked {
            SwapState::WowLocked {
                wow_lock_tx: recorded,
                adaptor_point,
                my_adaptor_pre_sig,
                ..
            } => {
                assert_eq!(*recorded, wow_lock_tx);
                assert_eq!(
                    *adaptor_point, alice_pub,
                    "Bob adapts against Alice's pubkey"
                );
                assert_ne!(
                    my_adaptor_pre_sig.r_plus_t, [0u8; 32],
                    "pre-sig R_T must not be zero"
                );
                assert_ne!(
                    my_adaptor_pre_sig.s_prime, [0u8; 32],
                    "pre-sig s' must not be zero"
                );
            }
            _ => panic!("expected WowLocked after Bob records the WOW lock"),
        }

        // Bob's local state should accept Alice's revealed secret, not his own.
        let completed = locked.complete_with_claim(alice_secret).unwrap();
        assert!(matches!(completed, SwapState::Complete { .. }));
    }

    #[test]
    fn complete_with_claim_accepts_correct_k_b_from_xmr_locked() {
        let (alice, _, bob, bob_secret) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice_locked = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();
        let locked = alice_locked.record_xmr_lock([0xAA; 32]).unwrap();
        let result = locked.complete_with_claim(bob_secret);
        assert!(
            result.is_ok(),
            "correct counterparty secret must be accepted"
        );
        assert!(matches!(result.unwrap(), SwapState::Complete { .. }));
    }

    #[test]
    fn complete_with_claim_rejects_wrong_k_b_from_xmr_locked() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice_locked = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();
        let locked = alice_locked.record_xmr_lock([0xAA; 32]).unwrap();
        let wrong_k_b = [0xBBu8; 32];
        let result = locked.complete_with_claim(wrong_k_b);
        assert!(
            result.is_err(),
            "wrong counterparty secret must be rejected"
        );
    }

    #[test]
    fn full_state_machine_round_trip_with_real_keys() {
        // Per D-09: real Ed25519 keys end-to-end, no stubs
        let (alice, alice_secret, bob, bob_secret) = make_alice_bob();
        let (alice_pub, alice_proof) = get_pubkey_and_proof(&alice);
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);

        // Alice side: Bob's secret is revealed against Alice's XmrLocked state.
        let alice2 = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();
        let alice3 = alice2.derive_joint_addresses().unwrap();
        let alice_locked = alice3.record_xmr_lock([0xAA; 32]).unwrap();
        let alice_complete = alice_locked.complete_with_claim(bob_secret).unwrap();
        assert!(matches!(alice_complete, SwapState::Complete { .. }));

        // Bob side: Alice's secret is revealed against Bob's WowLocked state.
        let bob2 = bob
            .receive_counterparty_key(alice_pub, &alice_proof)
            .unwrap();
        let bob3 = bob2.derive_joint_addresses().unwrap();
        let bob_locked = bob3.record_wow_lock([0xBB; 32]).unwrap();
        let bob_complete = bob_locked.complete_with_claim(alice_secret).unwrap();
        assert!(matches!(bob_complete, SwapState::Complete { .. }));
    }

    #[test]
    fn complete_with_refund_transitions_from_xmr_locked() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice_locked = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap()
            .record_xmr_lock([0xAA; 32])
            .unwrap();
        let refund_hash = [0xCC; 32];

        let refunded = alice_locked.complete_with_refund(refund_hash).unwrap();
        match refunded {
            SwapState::Refunded { refund_tx_hash, .. } => {
                assert_eq!(refund_tx_hash, refund_hash);
            }
            _ => panic!("expected Refunded after XmrLocked refund transition"),
        }
    }

    #[test]
    fn complete_with_refund_transitions_from_wow_locked() {
        let (alice, _, bob, _) = make_alice_bob();
        let (alice_pub, alice_proof) = get_pubkey_and_proof(&alice);
        let bob_locked = bob
            .receive_counterparty_key(alice_pub, &alice_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap()
            .record_wow_lock([0xBB; 32])
            .unwrap();
        let refund_hash = [0xDD; 32];

        let refunded = bob_locked.complete_with_refund(refund_hash).unwrap();
        match refunded {
            SwapState::Refunded { refund_tx_hash, .. } => {
                assert_eq!(refund_tx_hash, refund_hash);
            }
            _ => panic!("expected Refunded after WowLocked refund transition"),
        }
    }

    #[test]
    fn validate_timelocks_succeeds_with_valid_params() {
        let (xmr_h, wow_h) = validate_timelocks(100, 100, 500, 1000).unwrap();
        assert_eq!(xmr_h, 600);
        assert_eq!(wow_h, 1100);
    }

    #[test]
    fn validate_timelocks_fails_ordering() {
        // xmr_refund_height=300, wow_refund_height=300 => 300 <= 300 + 100 = 400 => fail
        let result = validate_timelocks(100, 100, 200, 200);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must be >"), "error: {err}");
    }

    #[test]
    fn validate_timelocks_fails_too_short() {
        let result = validate_timelocks(100, 100, 5, 5);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"), "error: {err}");
    }

    #[test]
    fn phase13_observed_refund_timing_derives_heights_from_recorded_base_heights() {
        let params = sample_params();
        params.validate_observed_refund_timing().unwrap();
        let observation = params.require_observed_refund_timing().unwrap();
        assert_eq!(observation.source, RefundTimingSource::DaemonHeightQuery);
    }

    #[test]
    fn phase13_observed_refund_timing_rejects_missing_basis() {
        let params = SwapParams {
            refund_timing: None,
            ..sample_params()
        };

        let err = params
            .validate_observed_refund_timing()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Phase 13 timing basis missing"),
            "error: {err}"
        );
    }

    #[test]
    fn phase13_observed_refund_timing_rejects_mismatched_heights() {
        let mut params = sample_params();
        params.xmr_refund_height += 1;

        let err = params
            .validate_observed_refund_timing()
            .unwrap_err()
            .to_string();
        assert!(err.contains("timing basis mismatch"), "error: {err}");
    }

    #[test]
    fn restore_secret_into_key_generation() {
        let mut params = sample_params();
        params.amount_xmr = 1_000;
        params.amount_wow = 500;
        let (state, secret) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

        // Serialize (zeroes secret) then restore
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: SwapState = serde_json::from_str(&json).unwrap();
        match &deserialized {
            SwapState::KeyGeneration { secret_bytes, .. } => {
                assert_eq!(
                    *secret_bytes, [0u8; 32],
                    "serde(skip) should zero the secret"
                );
            }
            _ => panic!("wrong state"),
        }

        let restored = restore_secret_into_state(deserialized, secret).unwrap();
        match &restored {
            SwapState::KeyGeneration { secret_bytes, .. } => {
                assert_eq!(*secret_bytes, secret, "secret must be restored");
            }
            _ => panic!("wrong state"),
        }
    }

    #[test]
    fn restore_secret_rejects_wrong_secret() {
        let mut params = sample_params();
        params.amount_xmr = 1_000;
        params.amount_wow = 500;
        let (state, _secret) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: SwapState = serde_json::from_str(&json).unwrap();

        // Use a different random secret
        let wrong_secret = {
            let mut wrong_params = sample_params();
            wrong_params.amount_xmr = 1;
            wrong_params.amount_wow = 1;
            let (_, s) = SwapState::generate(SwapRole::Bob, wrong_params, &mut OsRng);
            s
        };
        let result = restore_secret_into_state(deserialized, wrong_secret);
        assert!(result.is_err(), "wrong secret must be rejected");
    }

    #[test]
    fn restore_secret_into_joint_address_phase() {
        let (alice, alice_secret, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let alice_ja = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();

        let json = serde_json::to_string(&alice_ja).unwrap();
        let deserialized: SwapState = serde_json::from_str(&json).unwrap();
        let restored = restore_secret_into_state(deserialized, alice_secret).unwrap();
        match &restored {
            SwapState::JointAddress { secret_bytes, .. } => {
                assert_eq!(*secret_bytes, alice_secret);
            }
            _ => panic!("wrong state"),
        }
    }

    #[test]
    fn restore_into_complete_fails() {
        let (alice, _, bob, bob_secret) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);
        let locked = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap()
            .record_xmr_lock([0xAA; 32])
            .unwrap();
        let complete = locked.complete_with_claim(bob_secret).unwrap();

        let result = restore_secret_into_state(complete, bob_secret);
        assert!(result.is_err(), "cannot restore secret into Complete state");
    }

    /// Regression test for bug #4: complete_with_adaptor_claim from XmrLocked state.
    ///
    /// The claim-wow flow requires extracting the counterparty's secret from their
    /// completed adaptor signature. This test exercises the XmrLocked arm (line 502)
    /// which was missing before the bug fix.
    #[test]
    fn test_complete_with_adaptor_claim_from_xmr_locked() {
        let (alice, _alice_secret, bob, bob_secret) = make_alice_bob();
        let (alice_pub, alice_proof) = get_pubkey_and_proof(&alice);
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);

        // Drive Alice to JointAddress
        let alice_ja = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();

        // Drive Bob to WowLocked (creates Bob's adaptor pre-sig)
        let bob_ja = bob
            .receive_counterparty_key(alice_pub, &alice_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap();
        let bob_wow_locked = bob_ja.record_wow_lock([0xBB; 32]).unwrap();

        // Extract Bob's pre-sig and create his ClaimProof (completed sig)
        let bob_pre_sig = match &bob_wow_locked {
            SwapState::WowLocked {
                my_adaptor_pre_sig, ..
            } => my_adaptor_pre_sig.clone(),
            _ => panic!("expected WowLocked"),
        };
        // Bob completes his own pre-sig with his secret (per protocol: main.rs line 927)
        let bob_secret_scalar = curve25519_dalek::scalar::Scalar::from_canonical_bytes(bob_secret)
            .into_option()
            .unwrap();
        let bob_completed_sig = bob_pre_sig.complete(&bob_secret_scalar).unwrap();

        // Drive Alice to XmrLocked (from JointAddress, creates Alice's pre-sig)
        let alice_xmr_locked = alice_ja.record_xmr_lock([0xAA; 32]).unwrap();

        // Alice receives Bob's pre-sig as counterparty_pre_sig
        let alice_with_presig = alice_xmr_locked
            .receive_counterparty_pre_sig(bob_pre_sig)
            .unwrap();

        // Alice extracts Bob's secret via adaptor sig atomicity
        let (complete_state, extracted_scalar) = alice_with_presig
            .complete_with_adaptor_claim(&bob_completed_sig)
            .unwrap();

        // Verify we reached Complete state
        assert!(matches!(complete_state, SwapState::Complete { .. }));

        // Verify the extracted scalar matches Bob's actual secret
        assert_eq!(
            extracted_scalar, bob_secret_scalar,
            "extracted secret must match Bob's actual secret scalar"
        );
    }

    /// Regression test for bug #4 error path: complete_with_adaptor_claim from
    /// XmrLocked without counterparty_pre_sig must fail with a clear error.
    #[test]
    fn test_complete_with_adaptor_claim_from_xmr_locked_no_presig() {
        let (alice, _, bob, _) = make_alice_bob();
        let (bob_pub, bob_proof) = get_pubkey_and_proof(&bob);

        // Drive Alice to XmrLocked without receiving counterparty pre-sig
        let alice_xmr_locked = alice
            .receive_counterparty_key(bob_pub, &bob_proof)
            .unwrap()
            .derive_joint_addresses()
            .unwrap()
            .record_xmr_lock([0xAA; 32])
            .unwrap();

        // Create a dummy completed sig
        let dummy_completed = CompletedSignature {
            r_t: [0u8; 32],
            s: [0u8; 32],
        };

        let result = alice_xmr_locked.complete_with_adaptor_claim(&dummy_completed);
        assert!(result.is_err(), "must fail without counterparty pre-sig");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("pre-sig"),
            "error should mention pre-sig, got: {err_msg}"
        );
    }
}
