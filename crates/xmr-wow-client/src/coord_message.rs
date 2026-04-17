//! Wire-format envelope for sharechain-relayed swap messages.
//! `maybe_encrypt` / `maybe_decrypt` are intentional no-ops; stubs for a future privacy layer.

use serde::{Deserialize, Serialize};

use crate::protocol_message::ProtocolMessage;

/// Serializes a 32-byte array as a 64-char lowercase hex string.
mod hex_array {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(&hex_str).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected exactly 32 bytes"))
    }
}

/// Errors produced by CoordMessage operations.
#[derive(Debug, thiserror::Error)]
pub enum CoordError {
    /// Serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Decryption failure (reserved for future privacy upgrade).
    #[error("decryption error: {0}")]
    Decryption(String),
}

/// Transport envelope for a swap protocol message relayed via the sharechain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordMessage {
    /// Swap identifier: 32 bytes serialized as a 64-char lowercase hex string.
    #[serde(with = "hex_array")]
    pub swap_id: [u8; 32],

    /// Opaque payload: a JSON-encoded `ProtocolMessage`, optionally encrypted.
    pub payload: Vec<u8>,

    /// Key-derivation hint for future encryption; `None` means plaintext.
    #[serde(default)]
    pub encryption_hint: Option<[u8; 32]>,
}

/// No-op encryption stub; returns `payload` unchanged.
pub fn maybe_encrypt(payload: Vec<u8>, _hint: Option<[u8; 32]>) -> Vec<u8> {
    payload
}

/// No-op decryption stub; returns `Ok(payload)` unchanged.
pub fn maybe_decrypt(payload: Vec<u8>, _hint: Option<[u8; 32]>) -> Result<Vec<u8>, CoordError> {
    Ok(payload)
}

/// JSON-serializes `msg` into a `CoordMessage` envelope for the given swap.
pub fn wrap_protocol_message(
    swap_id: [u8; 32],
    msg: &ProtocolMessage,
) -> Result<CoordMessage, CoordError> {
    let payload = serde_json::to_vec(msg).map_err(|e| CoordError::Serialization(e.to_string()))?;
    Ok(CoordMessage {
        swap_id,
        payload,
        encryption_hint: None,
    })
}

/// JSON-deserializes the payload of a `CoordMessage` into a `ProtocolMessage`.
pub fn unwrap_protocol_message(coord: &CoordMessage) -> Result<ProtocolMessage, CoordError> {
    serde_json::from_slice(&coord.payload).map_err(|e| CoordError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use xmr_wow_crypto::{AdaptorSignature, CompletedSignature, DleqProof, KeyContribution};

    fn make_dleq_proof() -> (DleqProof, [u8; 32]) {
        let contrib = KeyContribution::generate(&mut OsRng);
        let proof = DleqProof::prove(
            &contrib.secret,
            &contrib.public,
            b"xmr-wow-swap-v1",
            &mut OsRng,
        );
        (proof, contrib.public_bytes())
    }

    fn make_init() -> ProtocolMessage {
        let (proof, pubkey) = make_dleq_proof();
        ProtocolMessage::Init {
            pubkey,
            proof,
            amount_xmr: 1_000_000_000_000,
            amount_wow: 500_000_000_000_000,
            xmr_refund_delay_seconds: 2000,
            wow_refund_delay_seconds: 1000,
            refund_timing: None,
            alice_refund_address: None,
        }
    }

    fn make_response() -> ProtocolMessage {
        let (proof, pubkey) = make_dleq_proof();
        ProtocolMessage::Response {
            pubkey,
            proof,
            bob_refund_address: None,
            refund_artifact: None,
        }
    }

    fn make_adaptor_pre_sig() -> ProtocolMessage {
        ProtocolMessage::AdaptorPreSig {
            pre_sig: AdaptorSignature {
                r_plus_t: [0xAA; 32],
                s_prime: [0xBB; 32],
            },
        }
    }

    fn make_claim_proof() -> ProtocolMessage {
        ProtocolMessage::ClaimProof {
            completed_sig: CompletedSignature {
                r_t: [0xCC; 32],
                s: [0xDD; 32],
            },
        }
    }

    /// CoordMessage serializes to JSON with exactly the three expected fields
    /// and correct types.
    #[test]
    fn coord_message_json_has_three_fields() {
        let swap_id = [0x01u8; 32];
        let msg = make_init();
        let coord = wrap_protocol_message(swap_id, &msg).unwrap();
        let json: serde_json::Value = serde_json::to_value(&coord).unwrap();

        assert!(json.get("swap_id").is_some(), "must have swap_id field");
        assert!(json.get("payload").is_some(), "must have payload field");
        assert!(
            json.get("encryption_hint").is_some(),
            "must have encryption_hint field"
        );

        // Verify types
        assert!(json["swap_id"].is_string(), "swap_id must be a string");
        assert!(json["payload"].is_array(), "payload must be an array");
    }

    /// `encryption_hint: None` serializes as JSON `null`.
    #[test]
    fn encryption_hint_none_serializes_as_null() {
        let swap_id = [0x02u8; 32];
        let msg = make_init();
        let coord = wrap_protocol_message(swap_id, &msg).unwrap();
        let json: serde_json::Value = serde_json::to_value(&coord).unwrap();

        assert!(
            json["encryption_hint"].is_null(),
            "encryption_hint must serialize as null when None"
        );
    }

    /// A JSON blob missing the `encryption_hint` field deserializes successfully
    /// (serde default kicks in).
    #[test]
    fn missing_encryption_hint_deserializes_ok() {
        let json = r#"{"swap_id":"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd","payload":[1,2,3]}"#;
        let coord: CoordMessage =
            serde_json::from_str(json).expect("should deserialize without encryption_hint");
        assert!(coord.encryption_hint.is_none());
    }

    /// `swap_id` [0xAA; 32] serializes as the lowercase hex string "aa" * 32.
    #[test]
    fn swap_id_serializes_as_hex() {
        let swap_id = [0xAAu8; 32];
        let coord = CoordMessage {
            swap_id,
            payload: vec![],
            encryption_hint: None,
        };
        let json: serde_json::Value = serde_json::to_value(&coord).unwrap();
        let expected = "aa".repeat(32);
        assert_eq!(json["swap_id"].as_str().unwrap(), &expected);
    }

    /// The outer CoordMessage JSON must NOT contain a "type" field at the top
    /// level: variant information is hidden inside `payload`.
    #[test]
    fn variant_type_does_not_leak_into_outer_json() {
        let swap_id = [0x03u8; 32];
        let msg = make_init();
        let coord = wrap_protocol_message(swap_id, &msg).unwrap();
        let json: serde_json::Value = serde_json::to_value(&coord).unwrap();

        assert!(
            json.get("type").is_none(),
            "variant 'type' field must not appear in CoordMessage JSON"
        );
    }

    fn round_trip(msg: ProtocolMessage) {
        let swap_id = [0x55u8; 32];
        let coord = wrap_protocol_message(swap_id, &msg).unwrap();
        assert!(!coord.payload.is_empty(), "payload must be non-empty");

        let recovered = unwrap_protocol_message(&coord).unwrap();

        // We verify variant identity; field equality via re-serialization.
        let orig_json = serde_json::to_string(&msg).unwrap();
        let rec_json = serde_json::to_string(&recovered).unwrap();
        assert_eq!(
            orig_json, rec_json,
            "round-trip must produce identical JSON"
        );
    }

    #[test]
    fn round_trip_init() {
        round_trip(make_init());
    }

    #[test]
    fn round_trip_response() {
        round_trip(make_response());
    }

    #[test]
    fn round_trip_adaptor_pre_sig() {
        round_trip(make_adaptor_pre_sig());
    }

    #[test]
    fn round_trip_claim_proof() {
        round_trip(make_claim_proof());
    }

    #[test]
    fn maybe_encrypt_passthrough() {
        let payload = vec![1u8, 2, 3, 42];
        let out = maybe_encrypt(payload.clone(), None);
        assert_eq!(out, payload, "maybe_encrypt must return payload unchanged");
    }

    #[test]
    fn maybe_decrypt_passthrough() {
        let payload = vec![7u8, 8, 9, 100];
        let out = maybe_decrypt(payload.clone(), None).unwrap();
        assert_eq!(
            out, payload,
            "maybe_decrypt must return Ok(payload) unchanged"
        );
    }
}
