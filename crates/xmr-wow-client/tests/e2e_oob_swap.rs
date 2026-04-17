// e2e_oob_swap.rs
//
// Full out-of-band swap integration test: Alice and Bob drive the complete swap
// state machine from KeyGeneration through SwapState::Complete using direct
// ProtocolMessage routing with no sharechain code.
//
// Structural proof: no sharechain crate imports anywhere in this file.
// Runtime proof: OobMessenger ZST assertion at the end of the test.

use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use xmr_wow_client::{
    build_observed_refund_timing, decode_message, encode_message, OobMessenger, ProtocolMessage,
    SwapParams, SwapRole, SwapState,
};
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

/// Drives Alice and Bob through the full swap state machine:
///   KeyGeneration -> DleqExchange -> JointAddress -> WowLocked/XmrLocked
///   -> pre-sig exchange -> Complete
///
/// Messages are exchanged as direct Rust values (no network, no daemon, no
/// sharechain node). The test proves the OOB transport path is pure:
///   - No sharechain code in the execution path (structural: zero imports).
///   - OobMessenger is a zero-size type (runtime assertion).
///   - OOB encode/decode round-trips through the xmrwow1: prefix format.
#[test]
fn oob_transport_full_swap_init_through_claim() {
    let params = sample_params();
    let (alice, alice_secret) = SwapState::generate(SwapRole::Alice, params.clone(), &mut OsRng);
    let (bob, bob_secret) = SwapState::generate(SwapRole::Bob, params.clone(), &mut OsRng);

    let (alice_pub, alice_proof) = match &alice {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected KeyGeneration"),
    };
    let (bob_pub, bob_proof) = match &bob {
        SwapState::KeyGeneration {
            my_pubkey,
            my_proof,
            ..
        } => (*my_pubkey, my_proof.clone()),
        _ => panic!("expected KeyGeneration"),
    };

    let init_proto = ProtocolMessage::Init {
        pubkey: alice_pub,
        proof: alice_proof.clone(),
        amount_xmr: params.amount_xmr,
        amount_wow: params.amount_wow,
        xmr_refund_delay_seconds: params.xmr_refund_delay_seconds,
        wow_refund_delay_seconds: params.wow_refund_delay_seconds,
        refund_timing: params.refund_timing.clone(),
        alice_refund_address: params.alice_refund_address.clone(),
    };
    let encoded = encode_message(&init_proto);
    assert!(
        encoded.starts_with("xmrwow1:"),
        "OOB message must use xmrwow1: prefix, got: {}",
        &encoded[..encoded.len().min(30)]
    );
    let decoded = decode_message(&encoded).unwrap();
    assert!(
        matches!(decoded, ProtocolMessage::Init { .. }),
        "OOB encode/decode round-trip must preserve Init variant"
    );

    let alice = alice
        .receive_counterparty_key(bob_pub, &bob_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();
    let bob = bob
        .receive_counterparty_key(alice_pub, &alice_proof)
        .unwrap()
        .derive_joint_addresses()
        .unwrap();

    assert_eq!(
        alice.swap_id().unwrap(),
        bob.swap_id().unwrap(),
        "swap_id must match between Alice and Bob"
    );

    let bob = bob.record_wow_lock([0xBBu8; 32]).unwrap();
    assert!(
        matches!(bob, SwapState::WowLocked { .. }),
        "Bob must be in WowLocked state after record_wow_lock"
    );

    let alice = alice.record_xmr_lock([0xAAu8; 32]).unwrap();
    assert!(
        matches!(alice, SwapState::XmrLocked { .. }),
        "Alice must be in XmrLocked state after record_xmr_lock"
    );

    let bob_pre_sig = match &bob {
        SwapState::WowLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected WowLocked after record_wow_lock"),
    };
    let alice_pre_sig = match &alice {
        SwapState::XmrLocked {
            my_adaptor_pre_sig, ..
        } => my_adaptor_pre_sig.clone(),
        _ => panic!("expected XmrLocked after record_xmr_lock"),
    };

    let alice = alice
        .receive_counterparty_pre_sig(bob_pre_sig.clone())
        .expect("Alice must accept Bob's pre-sig");
    let bob = bob
        .receive_counterparty_pre_sig(alice_pre_sig.clone())
        .expect("Bob must accept Alice's pre-sig");

    let bob_secret_scalar = Scalar::from_canonical_bytes(bob_secret)
        .into_option()
        .expect("Bob's secret must be a valid canonical scalar");
    let bob_completed_sig = bob_pre_sig
        .complete(&bob_secret_scalar)
        .expect("Bob must be able to complete his pre-sig with his secret");

    let (alice_complete, extracted_bob_secret) = alice
        .complete_with_adaptor_claim(&bob_completed_sig)
        .expect("Alice must complete with Bob's completed sig");

    assert!(
        matches!(
            &alice_complete,
            SwapState::Complete {
                role: SwapRole::Alice,
                ..
            }
        ),
        "Alice must reach Complete state with Alice role"
    );
    assert_eq!(
        extracted_bob_secret, bob_secret_scalar,
        "Alice must extract Bob's secret correctly"
    );

    let alice_secret_scalar = Scalar::from_canonical_bytes(alice_secret)
        .into_option()
        .expect("Alice's secret must be a valid canonical scalar");
    let alice_completed_sig = alice_pre_sig
        .complete(&alice_secret_scalar)
        .expect("Alice must be able to complete her pre-sig with her secret");

    let alice_extracted = match &bob {
        SwapState::WowLocked {
            counterparty_pre_sig: Some(cp_pre_sig),
            ..
        } => cp_pre_sig
            .extract_secret(&alice_completed_sig)
            .expect("Bob must extract Alice's secret from her completed sig"),
        _ => panic!(
            "expected WowLocked with counterparty_pre_sig after receive_counterparty_pre_sig"
        ),
    };

    assert_eq!(
        alice_extracted, alice_secret_scalar,
        "Bob must extract Alice's secret correctly"
    );

    let bob_complete = bob
        .complete_with_claim(alice_extracted.to_bytes())
        .expect("Bob must complete with Alice's revealed secret");

    assert!(
        matches!(
            &bob_complete,
            SwapState::Complete {
                role: SwapRole::Bob,
                ..
            }
        ),
        "Bob must reach Complete state with Bob role"
    );

    // Final assertions: both sides Complete with matching swap_ids.
    assert!(
        matches!(&alice_complete, SwapState::Complete { .. }),
        "Alice must be Complete"
    );
    assert!(
        matches!(&bob_complete, SwapState::Complete { .. }),
        "Bob must be Complete"
    );

    let alice_swap_id = alice_complete
        .swap_id()
        .expect("Complete state must have swap_id");
    let bob_swap_id = bob_complete
        .swap_id()
        .expect("Complete state must have swap_id");
    assert_eq!(
        alice_swap_id, bob_swap_id,
        "Alice and Bob must have matching swap_ids at Complete"
    );

    // Structural proof: OobMessenger is a ZST.
    assert_eq!(
        std::mem::size_of::<OobMessenger>(),
        0,
        "OobMessenger must be a ZST; no sharechain fields"
    );
}
