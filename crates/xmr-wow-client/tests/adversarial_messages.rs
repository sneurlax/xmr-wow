use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, decode_message, unwrap_protocol_message, wrap_protocol_message,
    CoordMessage, ProtocolMessage, SwapError, SwapParams, SwapRole, SwapState,
};
use xmr_wow_crypto::{AdaptorSignature, CompletedSignature, DleqProof, KeyContribution};
use xmr_wow_test_utils::assert_hostile_rejection;

fn sample_params() -> SwapParams {
    let (refund_timing, xmr_refund_delay_seconds, wow_refund_delay_seconds) =
        build_observed_refund_timing(100, 200, 500, 800).unwrap();
    SwapParams {
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_delay_seconds,
        wow_refund_delay_seconds,
        refund_timing: Some(refund_timing),
        alice_refund_address: Some("alice-refund-addr".into()),
        bob_refund_address: Some("bob-refund-addr".into()),
    }
}

fn make_alice_bob(params: SwapParams) -> (SwapState, SwapState) {
    let (alice, _) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, _) = SwapState::generate(SwapRole::Bob, params, &mut OsRng);
    (alice, bob)
}

fn extract_pubkey_and_proof(state: &SwapState) -> ([u8; 32], DleqProof) {
    match state {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected KeyGeneration state"),
    }
}

fn advance_to_joint_address() -> (SwapState, SwapState) {
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let (alice_pub, alice_proof) = extract_pubkey_and_proof(&alice);

    let alice_joint = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    let bob_joint = bob
        .receive_counterparty_key(alice_pub, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    (alice_joint, bob_joint)
}

fn advance_to_xmr_locked() -> (SwapState, SwapState) {
    let (alice_joint, bob_joint) = advance_to_joint_address();

    // Bob locks WOW first
    let bob_wow = bob_joint.record_wow_lock([0xBB; 32]).unwrap();
    // Alice locks XMR
    let alice_xmr = alice_joint.record_xmr_lock([0xAA; 32]).unwrap();

    (alice_xmr, bob_wow)
}

#[test]
fn test_malformed_message_rejected() {
    let result: Result<ProtocolMessage, SwapError> = decode_message("garbage_bytes_not_valid");
    assert_hostile_rejection!(
        result,
        stage = "message_decode",
        reason = "missing protocol prefix",
        strategy = "unknown"
    );
}

#[test]
fn test_truncated_base64_rejected() {
    let result: Result<ProtocolMessage, SwapError> = decode_message("xmrwow1:!!!not-base64!!!");
    assert_hostile_rejection!(
        result,
        stage = "message_decode",
        reason = "base64 decode failed",
        strategy = "unknown"
    );
}

#[test]
fn test_valid_base64_invalid_json_rejected() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    let bad_json = BASE64.encode(b"\xff\xfe garbage");
    let encoded = format!("xmrwow1:{bad_json}");
    let result: Result<ProtocolMessage, SwapError> = decode_message(&encoded);
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("JSON decode failed"),
        "expected JSON decode error, got: {err}"
    );
}

#[test]
fn test_wrong_type_at_wrong_step_pre_sig_on_keygen() {
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    let dummy_pre_sig = AdaptorSignature {
        r_plus_t: [0xAA; 32],
        s_prime: [0xBB; 32],
    };

    let result = alice.receive_counterparty_pre_sig(dummy_pre_sig);
    assert_hostile_rejection!(
        result,
        stage = "state_transition",
        reason = "invalid state transition",
        strategy = "unknown"
    );
}

#[test]
fn test_wrong_type_at_wrong_step_adaptor_claim_on_keygen() {
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    use xmr_wow_crypto::CompletedSignature;
    let dummy_completed = CompletedSignature {
        r_t: [0xCC; 32],
        s: [0xDD; 32],
    };

    let err = alice
        .complete_with_adaptor_claim(&dummy_completed)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition, got: {err}"
    );
}

#[test]
fn test_wrong_type_at_wrong_step_adaptor_claim_on_joint_address() {
    // complete_with_adaptor_claim is only valid from WowLocked/XmrLocked with a stored pre-sig
    let (alice_joint, _bob_joint) = advance_to_joint_address();

    use xmr_wow_crypto::CompletedSignature;
    let dummy_completed = CompletedSignature {
        r_t: [0xCC; 32],
        s: [0xDD; 32],
    };

    let err = alice_joint
        .complete_with_adaptor_claim(&dummy_completed)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition from JointAddress, got: {err}"
    );
}

#[test]
fn test_out_of_order_record_wow_lock_from_xmr_locked() {
    let (alice_xmr_locked, _bob) = advance_to_xmr_locked();

    let err = alice_xmr_locked
        .record_wow_lock([0xFF; 32])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition, got: {err}"
    );
}

#[test]
fn test_out_of_order_receive_key_from_dleq_exchange() {
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);
    let alice_dleq = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();

    let err = alice_dleq
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition on second receive_counterparty_key, got: {err}"
    );
}

#[test]
fn test_out_of_order_record_xmr_lock_from_keygen() {
    let params = sample_params();
    let (alice, _) = SwapState::generate(SwapRole::Alice, params, &mut OsRng);

    let err = alice.record_xmr_lock([0xAA; 32]).unwrap_err().to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition from KeyGeneration, got: {err}"
    );
}

#[test]
fn test_replayed_message_second_key_exchange_fails() {
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);

    let alice_dleq = alice.receive_counterparty_key(bob_pub, &bob_proof).unwrap();

    let err = alice_dleq
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid state transition"),
        "expected InvalidTransition on replay, got: {err}"
    );
}

#[test]
fn test_replayed_pre_sig_garbage_rejected() {
    let (alice_xmr, _bob_wow) = advance_to_xmr_locked();

    // zero r_plus_t is not a valid curve point
    let garbage_pre_sig = AdaptorSignature {
        r_plus_t: [0x00; 32],
        s_prime: [0x00; 32],
    };
    let err = alice_xmr
        .receive_counterparty_pre_sig(garbage_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("pre-sig verification failed") || err.contains("crypto error"),
        "expected pre-sig verification failure on garbage, got: {err}"
    );
}

#[test]
fn test_wrong_swap_id_pre_sig_rejected() {
    // Two independent swaps; pre-sig from swap2 fed to swap1 must be rejected.
    let (alice1_xmr, _bob1_wow) = advance_to_xmr_locked();
    let (_alice2_xmr, bob2_wow) = advance_to_xmr_locked();

    let bob2_pre_sig = match &bob2_wow {
        SwapState::WowLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected WowLocked"),
    };

    let err = alice1_xmr
        .receive_counterparty_pre_sig(bob2_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("pre-sig verification failed") || err.contains("crypto error"),
        "expected pre-sig rejection for wrong swap_id, got: {err}"
    );
}

#[test]
fn test_wrong_adaptor_point_fails() {
    // Pre-sig signed under a different adaptor point must be rejected even when
    // the swap_id matches.
    let (alice_xmr, _bob_wow) = advance_to_xmr_locked();

    let swap_id = match &alice_xmr {
        SwapState::XmrLocked { addresses, .. } => addresses.swap_id,
        _ => panic!("expected XmrLocked"),
    };

    let signer_contrib = KeyContribution::generate(&mut OsRng);
    let wrong_adaptor_contrib = KeyContribution::generate(&mut OsRng);

    let wrong_adaptor_pre_sig = AdaptorSignature::sign(
        &signer_contrib.secret,
        &signer_contrib.public,
        &swap_id,
        &wrong_adaptor_contrib.public, // not Alice's actual pubkey
        &mut OsRng,
    );

    let err = alice_xmr
        .receive_counterparty_pre_sig(wrong_adaptor_pre_sig)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("pre-sig verification failed") || err.contains("crypto error"),
        "expected wrong-adaptor rejection, got: {err}"
    );
}

#[test]
fn test_wrong_topic_structural_prevention() {
    // Unknown variants are rejected at deserialization; the closed enum is the enforcement.
    let wrong_topic_json = r#"{"UnknownTopic":{"data":"test"}}"#;
    let bad_result: Result<ProtocolMessage, _> = decode_message(wrong_topic_json);
    assert!(
        bad_result.is_err(),
        "unknown topic rejected at deserialization layer"
    );

    // A misspelled valid variant also fails
    let misspelled_json = r#"{"AdaptorPresig":{"pre_sig":[0;32]}}"#;
    let bad_result2: Result<ProtocolMessage, _> = decode_message(misspelled_json);
    assert!(
        bad_result2.is_err(),
        "misspelled topic rejected at deserialization layer"
    );
}

// CoordMessage envelope tests document which layer is responsible for each defense:
//   - Class 1 (wrong swap_id):     unwrap succeeds; receiver must filter by swap_id
//   - Class 2 (malformed payload): unwrap fails;    CoordError returned immediately
//   - Class 3 (replayed envelope): unwrap succeeds; state machine must reject replay
//   - Class 4 (cross-swap route):  unwrap succeeds; application must verify swap_id

fn make_all_four_variants() -> Vec<(&'static str, ProtocolMessage)> {
    let contrib_init = KeyContribution::generate(&mut OsRng);
    let proof_init = DleqProof::prove(
        &contrib_init.secret,
        &contrib_init.public,
        b"xmr-wow-swap-v1",
        &mut OsRng,
    );
    let init = ProtocolMessage::Init {
        pubkey: contrib_init.public_bytes(),
        proof: proof_init,
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_delay_seconds: 2000,
        wow_refund_delay_seconds: 1000,
        refund_timing: None,
        alice_refund_address: Some("alice-refund-addr".into()),
    };

    let contrib_resp = KeyContribution::generate(&mut OsRng);
    let proof_resp = DleqProof::prove(
        &contrib_resp.secret,
        &contrib_resp.public,
        b"xmr-wow-swap-v1",
        &mut OsRng,
    );
    let response = ProtocolMessage::Response {
        pubkey: contrib_resp.public_bytes(),
        proof: proof_resp,
        bob_refund_address: Some("bob-refund-addr".into()),
        refund_artifact: None,
    };

    let adaptor_pre_sig = ProtocolMessage::AdaptorPreSig {
        pre_sig: AdaptorSignature {
            r_plus_t: [0xAA; 32],
            s_prime: [0xBB; 32],
        },
    };

    let claim_proof = ProtocolMessage::ClaimProof {
        completed_sig: CompletedSignature {
            r_t: [0x01u8; 32],
            s: [0x02u8; 32],
        },
    };

    vec![
        ("Init", init),
        ("Response", response),
        ("AdaptorPreSig", adaptor_pre_sig),
        ("ClaimProof", claim_proof),
    ]
}

#[test]
fn coord_envelope_wrong_swap_id_all_variants() {
    let correct_swap_id = [0x12u8; 32];
    let wrong_swap_id = [0xFFu8; 32];

    for (variant_name, msg) in make_all_four_variants() {
        let mut coord = wrap_protocol_message(correct_swap_id, &msg)
            .unwrap_or_else(|e| panic!("[{variant_name}] wrap failed: {e}"));

        coord.swap_id = wrong_swap_id;

        // unwrap_protocol_message does not check swap_id; filtering is the receiver's responsibility.
        let result = unwrap_protocol_message(&coord);
        assert!(
            result.is_ok(),
            "[{variant_name}] unwrap_protocol_message must succeed regardless of swap_id \
             (swap_id filtering is the receiver's responsibility, not the unwrap layer's); \
             got: {:?}",
            result.err()
        );

        assert_eq!(
            coord.swap_id, wrong_swap_id,
            "[{variant_name}] mutated swap_id must be present in envelope"
        );
        assert_ne!(
            coord.swap_id, correct_swap_id,
            "[{variant_name}] mutated swap_id must differ from the expected swap_id"
        );
    }
}

#[test]
fn coord_envelope_malformed_payload_all_variants() {
    let garbage_payloads: &[(&str, &[u8])] = &[
        ("random_bytes", &[0xFF, 0xFE, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]),
        ("null_bytes", &[0x00, 0x00, 0x00]),
        ("partial_json", b"{\"type\":\"Init\""),
        ("wrong_type_json", b"{\"not_a_protocol_message\": true}"),
    ];

    for (variant_name, _msg) in make_all_four_variants() {
        for (payload_desc, garbage) in garbage_payloads {
            let coord = CoordMessage {
                swap_id: [0x01u8; 32],
                payload: garbage.to_vec(),
                encryption_hint: None,
            };

            let result = unwrap_protocol_message(&coord);
            assert!(
                result.is_err(),
                "[{variant_name} / payload={payload_desc}] unwrap_protocol_message must fail \
                 on malformed payload bytes: garbage bytes are not valid JSON; \
                 unexpectedly got Ok"
            );
        }
    }
}

#[test]
fn coord_envelope_replayed_all_variants() {
    let swap_id = [0x55u8; 32];

    for (variant_name, msg) in make_all_four_variants() {
        let coord = wrap_protocol_message(swap_id, &msg)
            .unwrap_or_else(|e| panic!("[{variant_name}] wrap failed: {e}"));

        let replayed = coord.clone();

        // The envelope layer is stateless; replay detection is the state machine's job.
        let result_original = unwrap_protocol_message(&coord);
        let result_replayed = unwrap_protocol_message(&replayed);

        assert!(
            result_original.is_ok(),
            "[{variant_name}] original unwrap must succeed; got: {:?}",
            result_original.err()
        );
        assert!(
            result_replayed.is_ok(),
            "[{variant_name}] replayed unwrap must also succeed: replay detection is \
             the STATE MACHINE's responsibility, not the envelope layer's; \
             got: {:?}",
            result_replayed.err()
        );

        let orig_json =
            serde_json::to_string(&result_original.unwrap()).expect("serialization must not fail");
        let replay_json =
            serde_json::to_string(&result_replayed.unwrap()).expect("serialization must not fail");
        assert_eq!(
            orig_json, replay_json,
            "[{variant_name}] original and replayed envelopes must decode identically"
        );
    }
}

#[test]
fn coord_envelope_replayed_init_state_machine_rejects_second_application() {
    let swap_id = [0x55u8; 32];
    let params = sample_params();
    let (alice, bob) = make_alice_bob(params);

    let (bob_pub, bob_proof) = extract_pubkey_and_proof(&bob);

    // Wrap Bob's Init as a CoordMessage (simulating what the network would relay)
    let init_msg = ProtocolMessage::Init {
        pubkey: bob_pub,
        proof: bob_proof.clone(),
        amount_xmr: 1_000_000_000_000,
        amount_wow: 500_000_000_000_000,
        xmr_refund_delay_seconds: 2000,
        wow_refund_delay_seconds: 1000,
        refund_timing: None,
        alice_refund_address: None,
    };
    let coord = wrap_protocol_message(swap_id, &init_msg).unwrap();
    let replayed = coord.clone();

    let msg_first = unwrap_protocol_message(&coord).unwrap();
    let msg_second = unwrap_protocol_message(&replayed).unwrap();

    let alice_dleq = match msg_first {
        ProtocolMessage::Init { pubkey, proof, .. } => {
            alice.receive_counterparty_key(pubkey, &proof).unwrap()
        }
        _ => panic!("expected Init variant"),
    };

    let err = match msg_second {
        ProtocolMessage::Init { pubkey, proof, .. } => alice_dleq
            .receive_counterparty_key(pubkey, &proof)
            .unwrap_err(),
        _ => panic!("expected Init variant"),
    };
    assert!(
        err.to_string().contains("invalid state transition"),
        "state machine must reject replayed Init transition; got: {err}"
    );
}

#[test]
fn coord_envelope_cross_swap_routing_all_variants() {
    let swap_a = [0xAAu8; 32];
    let swap_b = [0xBBu8; 32];

    for (variant_name, msg) in make_all_four_variants() {
        let mut coord = wrap_protocol_message(swap_a, &msg)
            .unwrap_or_else(|e| panic!("[{variant_name}] wrap failed: {e}"));

        coord.swap_id = swap_b;

        // unwrap_protocol_message has no knowledge of sessions; the application must verify swap_id.
        let result = unwrap_protocol_message(&coord);
        assert!(
            result.is_ok(),
            "[{variant_name}] unwrap_protocol_message succeeds even after swap_id mutation: \
             cross-swap routing defense is the APPLICATION's responsibility; \
             got: {:?}",
            result.err()
        );

        assert_eq!(
            coord.swap_id, swap_b,
            "[{variant_name}] envelope carries swap_b's id after routing mutation"
        );
        assert_ne!(
            coord.swap_id, swap_a,
            "[{variant_name}] original swap_a id is no longer in the envelope"
        );
        let inner = result.unwrap();
        let inner_json = serde_json::to_string(&inner).expect("re-serialization must not fail");
        let orig_json = serde_json::to_string(&msg).expect("re-serialization must not fail");
        assert_eq!(
            inner_json, orig_json,
            "[{variant_name}] payload bytes unchanged by swap_id mutation: \
             cross-swap routing does not corrupt the inner message"
        );
    }
}
