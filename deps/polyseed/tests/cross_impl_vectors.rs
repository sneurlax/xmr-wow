//! Cross-implementation test vectors.

use polyseed::{Coin, Language, Polyseed};
use zeroize::Zeroizing;

fn rust_salt(coin: u16, birthday_encoded: u16, features: u8) -> [u8; 32] {
    let mut salt = [0u8; 32];
    salt[..12].copy_from_slice(b"POLYSEED key");
    salt[13] = 0xFF;
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    salt[16..20].copy_from_slice(&u32::from(coin).to_le_bytes());
    salt[20..24].copy_from_slice(&u32::from(birthday_encoded).to_le_bytes());
    salt[24..28].copy_from_slice(&u32::from(features).to_le_bytes());
    salt
}

fn c_reference_salt(coin: u32, birthday_encoded: u32, features: u32) -> [u8; 32] {
    let mut salt = [0u8; 32];
    salt[..12].copy_from_slice(b"POLYSEED key");
    salt[13] = 0xFF;
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    salt[16..20].copy_from_slice(&coin.to_le_bytes());
    salt[20..24].copy_from_slice(&birthday_encoded.to_le_bytes());
    salt[24..28].copy_from_slice(&features.to_le_bytes());
    salt
}

const POLYSEED_EPOCH: u64 = 1635768000;
const TIME_STEP: u64 = 2629746;
const DATE_BITS: u8 = 10;
const DATE_MASK: u16 = (1u16 << DATE_BITS) - 1;

fn birthday_encode(time: u64) -> u16 {
    u16::try_from((time.saturating_sub(POLYSEED_EPOCH) / TIME_STEP) & u64::from(DATE_MASK))
        .expect("value masked by 2**10 - 1 didn't fit into a u16")
}

#[test]
fn test_dart_vector_key_derivation() {
    let phrase = "unaware yard donate shallow slot sing oil oxygen \
                  loyal bench near hill surround forum execute lamp";
    let seed =
        Polyseed::from_string(Language::English, Zeroizing::new(phrase.to_string()), Coin::Monero, 0).unwrap();

    let key_hex = hex::encode(seed.key(Coin::Monero).as_ref());
    assert_eq!(key_hex, "cbbd142d38347773d44aa830f5f01442aa6d0d3bb48571884479531248e6fa1c");
}

#[test]
fn test_c_seed1_entropy() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    let seed =
        Polyseed::from_string(Language::English, Zeroizing::new(phrase.to_string()), Coin::Monero, 0).unwrap();

    assert_eq!(
        hex::encode(seed.entropy().as_ref()),
        "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000",
    );

    let expected_time: u64 = 1638446400;
    let diff = seed.birthday().abs_diff(expected_time);
    assert!(diff < TIME_STEP);
    assert_eq!(seed.features(), 0);
}

#[test]
fn test_c_seed2_spanish_entropy_and_birthday() {
    let phrase = "eje fin parte ce\u{0301}lebre tabu\u{0301} pestan\u{0303}a lienzo puma \
                  prisio\u{0301}n hora regalo lengua existir la\u{0301}piz lote sonoro";
    let seed =
        Polyseed::from_string(Language::Spanish, Zeroizing::new(phrase.to_string()), Coin::Monero, 0).unwrap();

    assert_eq!(
        hex::encode(seed.entropy().as_ref()),
        "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000",
    );

    let expected_time: u64 = 3118651200;
    let diff = seed.birthday().abs_diff(expected_time);
    assert!(diff < TIME_STEP);
    assert_eq!(seed.features(), 0);
    assert_eq!(birthday_encode(expected_time), 563);
}

#[test]
fn test_salt_construction_comparison() {
    {
        let rust = rust_salt(0, 1, 0);
        let c_ref = c_reference_salt(0, 1, 0);
        assert_eq!(
            hex::encode(&c_ref),
            "504f4c5953454544206b657900ffffff00000000010000000000000000000000"
        );
        assert_eq!(rust, c_ref);
    }

    {
        let rust = rust_salt(0, 563, 0);
        let c_ref = c_reference_salt(0, 563, 0);
        assert_eq!(
            hex::encode(&c_ref),
            "504f4c5953454544206b657900ffffff00000000330200000000000000000000"
        );
        assert_eq!(rust, c_ref);
    }

    {
        let rust = rust_salt(1, 1015, 1);
        let c_ref = c_reference_salt(1, 1015, 1);
        assert_eq!(
            hex::encode(&c_ref),
            "504f4c5953454544206b657900ffffff01000000f70300000100000000000000"
        );
        assert_eq!(rust, c_ref);
    }

    for coin in [0u16, 1, 2] {
        let rust = rust_salt(coin, 100, 0);
        let c_ref = c_reference_salt(u32::from(coin), 100, 0);
        assert_eq!(rust, c_ref);
    }
}

#[test]
fn test_multi_coin_support() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    let seed =
        Polyseed::from_string(Language::English, Zeroizing::new(phrase.to_string()), Coin::Monero, 0).unwrap();

    let key_monero = seed.key(Coin::Monero);
    let key_aeon = seed.key(Coin::Aeon);
    let key_wownero = seed.key(Coin::Wownero);

    assert_ne!(*key_monero, *key_aeon);
    assert_ne!(*key_monero, *key_wownero);
    assert_ne!(*key_aeon, *key_wownero);

    assert_eq!(*key_monero, *seed.key(Coin::Monero));
}

#[test]
fn test_c_seed3_aeon_salt_matches() {
    let c_salt_hex = "504f4c5953454544206b657900ffffff01000000f70300000100000000000000";
    let c_salt_bytes = hex::decode(c_salt_hex).unwrap();
    let rust_salt_bytes = rust_salt(1, 1015, 1);
    assert_eq!(rust_salt_bytes.as_slice(), c_salt_bytes.as_slice());
}

#[test]
fn test_nfc_vs_nfd_accent_handling_fixed() {
    let nfc_phrase = "eje fin parte c\u{00e9}lebre tabu\u{00fa} pestan\u{0303}a lienzo puma \
                      prisio\u{0301}n hora regalo lengua existir la\u{0301}piz lote sonoro";
    let nfd_phrase = "eje fin parte ce\u{0301}lebre tabu\u{0301} pestan\u{0303}a lienzo puma \
                      prisio\u{0301}n hora regalo lengua existir la\u{0301}piz lote sonoro";

    let nfd_result =
        Polyseed::from_string(Language::Spanish, Zeroizing::new(nfd_phrase.to_string()), Coin::Monero, 0);
    assert!(nfd_result.is_ok());

    let nfc_result =
        Polyseed::from_string(Language::Spanish, Zeroizing::new(nfc_phrase.to_string()), Coin::Monero, 0);
    assert!(nfc_result.is_ok());

    assert_eq!(nfd_result.unwrap(), nfc_result.unwrap());
}
