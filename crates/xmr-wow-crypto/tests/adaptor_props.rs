//! Property-based and KAT tests for adaptor signatures.
#![allow(non_snake_case)]

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use proptest::prelude::*;
use rand::rngs::OsRng;
use xmr_wow_crypto::AdaptorSignature;

fn scalar_bytes_strategy() -> impl Strategy<Value = [u8; 32]> {
    proptest::collection::vec(any::<u8>(), 32)
        .prop_map(|v| v.try_into().expect("vec of exactly 32 bytes"))
}

fn msg_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..128)
}

proptest! {
    /// sign -> verify_pre_sig round trip.
    #[test]
    fn adaptor_sign_verify_roundtrip(
        a_bytes in scalar_bytes_strategy(),
        t_bytes in scalar_bytes_strategy(),
        msg     in msg_strategy(),
    ) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let t = Scalar::from_bytes_mod_order(t_bytes);
        // skip degenerate zero scalars
        prop_assume!(a != Scalar::ZERO);
        prop_assume!(t != Scalar::ZERO);

        let A = a * G;
        let T = t * G;

        let pre = AdaptorSignature::sign(&a, &A, &msg, &T, &mut OsRng);
        prop_assert!(pre.verify_pre_sig(&A, &msg, &T).is_ok());
    }

    /// complete -> verify round trip.
    #[test]
    fn adaptor_complete_verify_roundtrip(
        a_bytes in scalar_bytes_strategy(),
        t_bytes in scalar_bytes_strategy(),
        msg     in msg_strategy(),
    ) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let t = Scalar::from_bytes_mod_order(t_bytes);
        prop_assume!(a != Scalar::ZERO);
        prop_assume!(t != Scalar::ZERO);

        let A = a * G;
        let T = t * G;

        let pre = AdaptorSignature::sign(&a, &A, &msg, &T, &mut OsRng);
        prop_assume!(pre.verify_pre_sig(&A, &msg, &T).is_ok());

        let completed = pre.complete(&t).unwrap();
        prop_assert!(completed.verify(&A, &msg).is_ok());
    }

    /// extract_secret recovers the original adaptor secret.
    #[test]
    fn adaptor_secret_extraction(
        a_bytes in scalar_bytes_strategy(),
        t_bytes in scalar_bytes_strategy(),
        msg     in msg_strategy(),
    ) {
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let t = Scalar::from_bytes_mod_order(t_bytes);
        prop_assume!(a != Scalar::ZERO);
        prop_assume!(t != Scalar::ZERO);

        let A = a * G;
        let T = t * G;

        let pre = AdaptorSignature::sign(&a, &A, &msg, &T, &mut OsRng);
        let completed = pre.complete(&t).unwrap();
        let recovered = pre.extract_secret(&completed).unwrap();
        prop_assert_eq!(recovered.to_bytes(), t.to_bytes());
    }

    /// Wrong adaptor secret must not produce a verifiable signature.
    #[test]
    fn adaptor_wrong_secret(
        a_bytes  in scalar_bytes_strategy(),
        t_bytes  in scalar_bytes_strategy(),
        t2_bytes in scalar_bytes_strategy(),
        msg      in msg_strategy(),
    ) {
        let a  = Scalar::from_bytes_mod_order(a_bytes);
        let t  = Scalar::from_bytes_mod_order(t_bytes);
        let t2 = Scalar::from_bytes_mod_order(t2_bytes);

        prop_assume!(a  != Scalar::ZERO);
        prop_assume!(t  != Scalar::ZERO);
        prop_assume!(t2 != Scalar::ZERO);
        // only interesting when t2 != t
        prop_assume!(t.to_bytes() != t2.to_bytes());

        let A = a * G;
        let T = t * G;

        let pre = AdaptorSignature::sign(&a, &A, &msg, &T, &mut OsRng);

        match pre.complete(&t2) {
            Err(_) => {}
            Ok(completed_wrong) => {
                prop_assert!(completed_wrong.verify(&A, &msg).is_err());
            }
        }
    }
}

/// KAT: fixed inputs exercise the full sign->verify->complete->extract chain.
#[test]
fn adaptor_kat_deterministic() {
    // fixed key material
    let a = Scalar::from_bytes_mod_order([1u8; 32]);
    let t = Scalar::from_bytes_mod_order([2u8; 32]);
    let A = a * G;
    let T = t * G;
    let msg = b"test-kat-vector";

    let pre = AdaptorSignature::sign(&a, &A, msg, &T, &mut OsRng);
    assert!(pre.verify_pre_sig(&A, msg, &T).is_ok());

    let completed = pre.complete(&t).unwrap();
    assert!(completed.verify(&A, msg).is_ok());

    let recovered = pre.extract_secret(&completed).unwrap();
    assert_eq!(recovered.to_bytes(), t.to_bytes());
}
