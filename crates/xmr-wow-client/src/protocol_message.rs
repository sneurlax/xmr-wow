//! Protocol message encoding for XMR-WOW atomic swap.
//!
//! Messages are exchanged between counterparties as `xmrwow1:<base64>` strings.
//! This format is human-friendly for manual copy-paste / DM exchange.
//!
//! The message envelope encodes any `Serialize + DeserializeOwned` type as:
//! 1. JSON serialize the message
//! 2. Base64-encode the JSON bytes (standard alphabet)
//! 3. Prepend the `xmrwow1:` prefix
//!
//! ## Protocol Flow
//!
//! 1. Alice -> Bob: `Init` with pubkey, proof, amounts, timelocks
//! 2. Bob -> Alice: `Response` with pubkey and proof
//! 3. Both: `AdaptorPreSig` after locking funds
//! 4. Claimer: `ClaimProof` with completed adaptor signature

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use xmr_wow_crypto::{AdaptorSignature, CompletedSignature, DleqProof};

use crate::swap_state::{PersistedRefundArtifact, RefundTimingObservation, SwapError};

/// Protocol message prefix for all XMR-WOW swap messages.
const PROTOCOL_PREFIX: &str = "xmrwow1:";

/// Protocol messages exchanged between swap counterparties.
///
/// Each variant corresponds to a step in the atomic swap protocol.
/// Messages are serialized to JSON, base64-encoded, and prefixed with `xmrwow1:`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProtocolMessage {
    /// Alice -> Bob: initiation with pubkey, proof, and swap params.
    Init {
        pubkey: [u8; 32],
        proof: DleqProof,
        amount_xmr: u64,
        amount_wow: u64,
        xmr_refund_delay_seconds: u64,
        wow_refund_delay_seconds: u64,
        #[serde(default)]
        refund_timing: Option<RefundTimingObservation>,
        #[serde(default)]
        alice_refund_address: Option<String>,
    },
    /// Bob -> Alice: response with pubkey and proof.
    Response {
        pubkey: [u8; 32],
        proof: DleqProof,
        #[serde(default)]
        bob_refund_address: Option<String>,
        #[serde(default)]
        refund_artifact: Option<PersistedRefundArtifact>,
    },
    /// Counterparty refund artifact exchanged before the risk-lock step.
    RefundArtifact { artifact: PersistedRefundArtifact },
    /// Adaptor pre-signature exchange (both parties send after locking).
    AdaptorPreSig { pre_sig: AdaptorSignature },
    /// Claim proof via completed adaptor signature.
    ///
    /// The counterparty extracts the secret using `pre_sig.extract_secret(completed)`.
    ClaimProof { completed_sig: CompletedSignature },
    /// Share secret scalar for cooperative refund tx construction.
    ///
    /// Sent when both parties agree to cancel the swap. The combined key
    /// `(k_a + k_b)` enables sweeping the joint address back to the original owners.
    RefundCooperate {
        /// The sender's secret scalar (k_a or k_b).
        secret_scalar: [u8; 32],
        /// The lock tx hash this refund cooperation is for.
        lock_tx_hash: [u8; 32],
    },
}

/// Encode a serializable value as an `xmrwow1:<base64>` string.
///
/// The value is JSON-serialized, then base64-encoded with the standard alphabet,
/// then prefixed with `xmrwow1:`.
pub fn encode_message<T: Serialize>(msg: &T) -> String {
    // String, Option) and DleqProof/AdaptorSignature which are also fully Serialize-able;
    // serde_json::to_string cannot fail on these types.
    let json = serde_json::to_string(msg).expect("message serialization should not fail");
    let b64 = BASE64.encode(json.as_bytes());
    format!("{}{}", PROTOCOL_PREFIX, b64)
}

/// Decode an `xmrwow1:<base64>` string into a deserialized value.
///
/// Strips the `xmrwow1:` prefix, base64-decodes, then JSON-deserializes.
/// Returns `SwapError::InvalidMessage` on any failure.
pub fn decode_message<T: DeserializeOwned>(encoded: &str) -> Result<T, SwapError> {
    let payload = encoded.strip_prefix(PROTOCOL_PREFIX).ok_or_else(|| {
        SwapError::InvalidMessage(format!("missing protocol prefix '{}'", PROTOCOL_PREFIX))
    })?;

    let bytes = BASE64
        .decode(payload)
        .map_err(|e| SwapError::InvalidMessage(format!("base64 decode failed: {}", e)))?;

    serde_json::from_slice(&bytes)
        .map_err(|e| SwapError::InvalidMessage(format!("JSON decode failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swap_state::RefundTimingSource;
    use rand::rngs::OsRng;
    use xmr_wow_crypto::{DleqProof, KeyContribution};

    fn make_test_init() -> ProtocolMessage {
        let contrib = KeyContribution::generate(&mut OsRng);
        let proof = DleqProof::prove(
            &contrib.secret,
            &contrib.public,
            b"xmr-wow-swap-v1",
            &mut OsRng,
        );
        ProtocolMessage::Init {
            pubkey: contrib.public_bytes(),
            proof,
            amount_xmr: 1_000_000_000_000,
            amount_wow: 500_000_000_000_000,
            xmr_refund_delay_seconds: 2000,
            wow_refund_delay_seconds: 1000,
            refund_timing: Some(RefundTimingObservation {
                xmr_base_height: 1950,
                wow_base_height: 700,
                xmr_refund_delay_seconds: 2000,
                wow_refund_delay_seconds: 1000,
                source: RefundTimingSource::DaemonHeightQuery,
            }),
            alice_refund_address: Some("alice-refund-address".into()),
        }
    }

    fn make_test_response() -> ProtocolMessage {
        let contrib = KeyContribution::generate(&mut OsRng);
        let proof = DleqProof::prove(
            &contrib.secret,
            &contrib.public,
            b"xmr-wow-swap-v1",
            &mut OsRng,
        );
        ProtocolMessage::Response {
            pubkey: contrib.public_bytes(),
            proof,
            bob_refund_address: Some("bob-refund-address".into()),
            refund_artifact: None,
        }
    }

    #[test]
    fn encode_produces_prefixed_string() {
        let msg = make_test_init();
        let encoded = encode_message(&msg);
        assert!(encoded.starts_with("xmrwow1:"), "must start with xmrwow1:");
    }

    #[test]
    fn init_round_trip() {
        let msg = make_test_init();
        let encoded = encode_message(&msg);
        let decoded: ProtocolMessage = decode_message(&encoded).unwrap();
        match (&msg, &decoded) {
            (
                ProtocolMessage::Init {
                    pubkey: a,
                    amount_xmr: ax,
                    refund_timing: at,
                    alice_refund_address: aa,
                    ..
                },
                ProtocolMessage::Init {
                    pubkey: b,
                    amount_xmr: bx,
                    refund_timing: bt,
                    alice_refund_address: ba,
                    ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(ax, bx);
                assert_eq!(at, bt);
                assert_eq!(aa, ba);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn init_message_round_trips_refund_timing_observation() {
        let msg = make_test_init();
        let encoded = encode_message(&msg);
        let decoded: ProtocolMessage = decode_message(&encoded).unwrap();

        match decoded {
            ProtocolMessage::Init {
                refund_timing,
                xmr_refund_delay_seconds,
                wow_refund_delay_seconds,
                ..
            } => {
                let refund_timing =
                    refund_timing.expect("init message should carry refund timing");
                assert_eq!(
                    refund_timing.xmr_refund_delay_seconds,
                    xmr_refund_delay_seconds
                );
                assert_eq!(
                    refund_timing.wow_refund_delay_seconds,
                    wow_refund_delay_seconds
                );
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_round_trip() {
        let msg = make_test_response();
        let encoded = encode_message(&msg);
        let decoded: ProtocolMessage = decode_message(&encoded).unwrap();
        match (&msg, &decoded) {
            (
                ProtocolMessage::Response {
                    pubkey: a,
                    bob_refund_address: ar,
                    refund_artifact: aa,
                    ..
                },
                ProtocolMessage::Response {
                    pubkey: b,
                    bob_refund_address: br,
                    refund_artifact: ba,
                    ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(ar, br);
                assert_eq!(aa, ba);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn init_and_response_messages_round_trip_refund_destinations() {
        let init = make_test_init();
        let encoded_init = encode_message(&init);
        let decoded_init: ProtocolMessage = decode_message(&encoded_init).unwrap();
        match decoded_init {
            ProtocolMessage::Init {
                alice_refund_address,
                ..
            } => assert_eq!(
                alice_refund_address.as_deref(),
                Some("alice-refund-address")
            ),
            _ => panic!("wrong init variant"),
        }

        let response = make_test_response();
        let encoded_response = encode_message(&response);
        let decoded_response: ProtocolMessage = decode_message(&encoded_response).unwrap();
        match decoded_response {
            ProtocolMessage::Response {
                bob_refund_address, ..
            } => assert_eq!(bob_refund_address.as_deref(), Some("bob-refund-address")),
            _ => panic!("wrong response variant"),
        }
    }

    #[test]
    fn decode_garbage_fails() {
        let result: Result<ProtocolMessage, _> = decode_message("garbage");
        assert!(result.is_err());
    }

    #[test]
    fn decode_invalid_base64_fails() {
        let result: Result<ProtocolMessage, _> = decode_message("xmrwow1:!!!invalid-base64");
        assert!(result.is_err());
    }

    #[test]
    fn adaptor_pre_sig_round_trip() {
        let pre_sig = AdaptorSignature {
            r_plus_t: [0xAA; 32],
            s_prime: [0xBB; 32],
        };
        let msg = ProtocolMessage::AdaptorPreSig { pre_sig };
        let encoded = encode_message(&msg);
        let decoded: ProtocolMessage = decode_message(&encoded).unwrap();
        match decoded {
            ProtocolMessage::AdaptorPreSig { pre_sig: d } => {
                assert_eq!(d.r_plus_t, [0xAA; 32]);
                assert_eq!(d.s_prime, [0xBB; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vts_refund_artifact_round_trips() {
        use xmr_wow_wallet::{RefundArtifact, RefundChain};
        let secret = curve25519_dalek::scalar::Scalar::from(7u64).to_bytes();
        let artifact: PersistedRefundArtifact = RefundArtifact::new_with_bits(
            RefundChain::Wow,
            [0x42; 32],
            "bob-refund-address",
            1,
            &secret,
            10,
            512,
        )
        .expect("test VTS artifact should build")
        .into();
        let msg = ProtocolMessage::RefundArtifact {
            artifact: artifact.clone(),
        };
        let encoded = encode_message(&msg);
        let decoded: ProtocolMessage = decode_message(&encoded).unwrap();
        match decoded {
            ProtocolMessage::RefundArtifact {
                artifact: decoded_artifact,
            } => {
                assert_eq!(decoded_artifact, artifact);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn claim_proof_round_trip() {
        let completed_sig = CompletedSignature {
            r_t: [0xCC; 32],
            s: [0xDD; 32],
        };
        let msg = ProtocolMessage::ClaimProof { completed_sig };
        let encoded = encode_message(&msg);
        let decoded: ProtocolMessage = decode_message(&encoded).unwrap();
        match decoded {
            ProtocolMessage::ClaimProof { completed_sig: d } => {
                assert_eq!(d.r_t, [0xCC; 32]);
                assert_eq!(d.s, [0xDD; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }
}
