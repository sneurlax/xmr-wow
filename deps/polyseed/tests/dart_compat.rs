//! Cross-implementation tests between Rust and Dart.

use polyseed::{Coin, Language, Polyseed};
use zeroize::Zeroizing;

// Shared test vectors produce identical keys

#[test]
fn vector1_unaware_yard_donate_key() {
    let phrase = "unaware yard donate shallow slot sing oil oxygen \
                  loyal bench near hill surround forum execute lamp";
    let expected_key = "cbbd142d38347773d44aa830f5f01442aa6d0d3bb48571884479531248e6fa1c";

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let key = seed.key(Coin::Monero);
    let key_hex = hex::encode(key.as_ref());

    assert_eq!(
        key_hex, expected_key,
        "Rust key must match Dart/cross-implementation reference for vector 1"
    );
}

#[test]
fn vector2_comic_blanket_chair_key() {
    let phrase = "comic blanket chair inject end snow rural improve cereal \
                  better initial replace ribbon brother gather unaware";
    let expected_key = "d85225a4fc7aaa3d3498831ab5e2bf83cc03f2e1e5af2597128f35af88112f7e";

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let key = seed.key(Coin::Monero);
    let key_hex = hex::encode(key.as_ref());

    assert_eq!(
        key_hex, expected_key,
        "Rust key must match Dart/cross-implementation reference for vector 2"
    );
}

#[test]
fn vector3_c_reference_english_raven_tail_swear_key() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    // This key was computed by the Dart implementation (with fixed store32)
    // Since birthday=1 (< 256), the salt is identical across all implementations.
    let expected_key = "21268a76048a3b25a4a9ac179d86b12fab5800b8d858da9facf4b0a778dc2840";

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Verify entropy matches C reference
    let entropy_hex = hex::encode(seed.entropy().as_ref());
    let expected_entropy = "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000";

    assert_eq!(
        entropy_hex, expected_entropy,
        "Entropy must match C reference"
    );

    let key = seed.key(Coin::Monero);
    let key_hex = hex::encode(key.as_ref());

    assert_eq!(
        key_hex, expected_key,
        "Rust key must match Dart key for C reference English seed"
    );
}

#[test]
fn vector4_c_reference_spanish_eje_fin_parte_key() {
    // Use composed (NFC) Unicode characters as in the Dart test
    let phrase = "eje fin parte c\u{00e9}lebre tab\u{00fa} pesta\u{00f1}a lienzo puma \
                  prisi\u{00f3}n hora regalo lengua existir l\u{00e1}piz lote sonoro";
    // This key was computed by the Dart implementation (with fixed store32)
    // birthday=563 (0x233), which previously triggered the store32 bug in Dart.
    // Now that store32 is fixed, Dart and Rust should agree.
    let expected_key = "35797a77a65f86ed1b78ddca70842b4cc9f6b11b3efadedb72a0d44a522b9a4f";

    let seed = Polyseed::from_string(
        Language::Spanish,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Verify entropy matches C reference
    let entropy_hex = hex::encode(seed.entropy().as_ref());
    let expected_entropy = "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000";

    assert_eq!(
        entropy_hex, expected_entropy,
        "Entropy must match C reference for Spanish seed"
    );

    let key = seed.key(Coin::Monero);
    let key_hex = hex::encode(key.as_ref());

    assert_eq!(
        key_hex, expected_key,
        "Rust key must match Dart key for C reference Spanish seed (birthday=563, store32 fix verified)"
    );
}

// Cross-check encryption

#[test]
fn encryption_unaware_yard_cakewallet() {
    let phrase = "unaware yard donate shallow slot sing oil oxygen \
                  loyal bench near hill surround forum execute lamp";
    let password = "CakeWallet";

    // Reference values from Dart test output
    let expected_encrypted_phrase =
        "arm dutch crystal reduce elephant mix squeeze garlic \
         slam brand tent seed rubber fame summer sample";
    let expected_encrypted_entropy = "444d5b411f8e34e5ff2c1b37dc2ef352764b3c";

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();
    let original_key_hex = hex::encode(seed.key(Coin::Monero).as_ref());

    // Encrypt
    let mut encrypted = seed.clone();
    encrypted.crypt(password);
    assert!(encrypted.is_encrypted(), "Seed should be encrypted after crypt()");

    // Verify encrypted entropy matches Dart
    let encrypted_entropy_hex = hex::encode(&encrypted.entropy()[.. 19]);

    assert_eq!(
        encrypted_entropy_hex, expected_encrypted_entropy,
        "Encrypted entropy must match Dart output"
    );

    // Verify encrypted phrase matches Dart
    let encrypted_phrase = encrypted.to_string(Coin::Monero);

    assert_eq!(
        *encrypted_phrase, expected_encrypted_phrase,
        "Encrypted phrase must match Dart output"
    );

    // Decrypt and verify round-trip
    encrypted.crypt(password);
    assert!(!encrypted.is_encrypted(), "Seed should be decrypted after second crypt()");

    let decrypted_key_hex = hex::encode(encrypted.key(Coin::Monero).as_ref());

    assert_eq!(
        decrypted_key_hex, original_key_hex,
        "Decrypted key must match original key"
    );
}

// Cross-check serialization

#[test]
fn serialization_unaware_yard_matches_dart() {
    let phrase = "unaware yard donate shallow slot sing oil oxygen \
                  loyal bench near hill surround forum execute lamp";
    // Reference: Dart serialized output (base64 and hex)
    let expected_hex = "504f4c59534545441600fed04c5330c96679e6121524e6bb6a5b93c733ff6377";

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let storage = seed.store();
    let storage_hex = hex::encode(storage.as_ref());

    assert_eq!(
        storage_hex, expected_hex,
        "Rust serialization must match Dart serialization byte-for-byte"
    );

    // Verify individual fields
    assert_eq!(&storage[.. 8], b"POLYSEED", "Header must be POLYSEED");
    assert_eq!(storage[29], 0xFF, "Extra byte must be 0xFF");

    // Parse the Dart base64 and compare
    let dart_bytes = base64_decode("UE9MWVNFRUQWAP7QTFMwyWZ55hIVJOa7aluTxzP/Y3c=");
    let dart_hex = hex::encode(&dart_bytes);
    assert_eq!(
        storage_hex, dart_hex,
        "Rust store() output must match Dart base64 decoded bytes"
    );
}

#[test]
fn deserialization_from_dart_base64() {
    let dart_bytes = base64_decode("UE9MWVNFRUQWAP7QTFMwyWZ55hIVJOa7aluTxzP/Y3c=");
    let storage: [u8; 32] = dart_bytes.try_into().expect("base64 should decode to 32 bytes");

    let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();

    // Verify birthday
    let expected_birthday: u64 = 1693622412;
    let actual_birthday = loaded.birthday();

    assert_eq!(
        actual_birthday, expected_birthday,
        "Deserialized birthday must match Dart expected value"
    );

    // Re-serialize and verify round-trip
    let reserialized = loaded.store();
    assert_eq!(
        reserialized.as_ref(),
        &storage,
        "Round-trip store/load must produce identical bytes"
    );
}

// Helpers

fn base64_decode(input: &str) -> Vec<u8> {
    // Simple base64 decoder (standard alphabet)
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> u8 {
        if c == b'=' {
            return 0;
        }
        ALPHABET.iter().position(|&x| x == c).expect("invalid base64 char") as u8
    }

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let mut result = Vec::new();

    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let a = val(chunk[0]);
        let b = val(chunk[1]);
        let c = if chunk.len() > 2 { val(chunk[2]) } else { 0 };
        let d = if chunk.len() > 3 { val(chunk[3]) } else { 0 };

        result.push((a << 2) | (b >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push((b << 4) | (c >> 2));
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push((c << 6) | d);
        }
    }

    result
}
