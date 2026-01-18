// Vendored upstream test code — lint suppressed
#![allow(clippy::needless_borrows_for_generic_args, clippy::manual_div_ceil, clippy::identity_op, clippy::erasing_op, dead_code, unused_variables)]
//! Tests verifying feature parity with C reference.

use polyseed::{Coin, Language, Polyseed, PolyseedError, get_feature};
use zeroize::Zeroizing;

/// Fixed 19-byte entropy from the English test vector.
fn test_entropy() -> Zeroizing<[u8; 32]> {
    let mut buf = [0u8; 32];
    let bytes = hex::decode("dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000")
        .unwrap();
    buf.copy_from_slice(&bytes);
    Zeroizing::new(buf)
}

/// English seed phrase from test vectors.
fn english_seed_phrase() -> Zeroizing<String> {
    Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    )
}

/// Japanese test vector entropy.
fn japanese_entropy() -> Zeroizing<[u8; 32]> {
    let mut buf = [0u8; 32];
    let bytes = hex::decode("94e6665518a6286c6e3ba508a2279eb62b771f00000000000000000000000000")
        .unwrap();
    buf.copy_from_slice(&bytes);
    Zeroizing::new(buf)
}

/// Japanese test vector birthday (decoded timestamp).
const JAPANESE_BIRTHDAY: u64 = 1679318722;

/// Korean test vector entropy.
fn korean_entropy() -> Zeroizing<[u8; 32]> {
    let mut buf = [0u8; 32];
    let bytes = hex::decode("684663fda420298f42ed94b2c512ed38ddf12b00000000000000000000000000")
        .unwrap();
    buf.copy_from_slice(&bytes);
    Zeroizing::new(buf)
}

/// Korean test vector birthday (decoded timestamp).
const KOREAN_BIRTHDAY: u64 = 1679317073;

// Encryption / decryption
#[test]
fn gap1_encryption_decryption_exists() {
    let seed = Polyseed::from_string(Language::English, english_seed_phrase(), Coin::Monero, 0).unwrap();
    let original_entropy = seed.entropy().clone();

    // crypt() now exists and works
    let mut encrypted = seed.clone();
    encrypted.crypt("test_password");
    assert!(encrypted.is_encrypted(), "Seed should be encrypted");
    assert_ne!(encrypted.entropy(), &original_entropy, "Entropy should change when encrypted");

    // Decrypt
    encrypted.crypt("test_password");
    assert!(!encrypted.is_encrypted(), "Seed should be decrypted");
    assert_eq!(encrypted.entropy(), &original_entropy, "Decrypted entropy should match");
    assert_eq!(encrypted, seed, "Decrypted seed should match original");
}

// Binary serialization
#[test]
fn gap2_binary_serialization_exists() {
    let seed = Polyseed::from_string(Language::English, english_seed_phrase(), Coin::Monero, 0).unwrap();

    // store() produces a 32-byte binary representation
    let storage = seed.store();
    assert_eq!(storage.len(), 32);
    assert_eq!(&storage[.. 8], b"POLYSEED", "Header should be POLYSEED");
    assert_eq!(storage[29], 0xFF, "Extra byte should be 0xFF");

    // load() reconstructs the seed from the binary representation
    let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert_eq!(seed, loaded, "Round-trip store/load should preserve the seed");
    assert_eq!(*seed.entropy(), *loaded.entropy());
    assert_eq!(seed.birthday(), loaded.birthday());
    assert_eq!(seed.features(), loaded.features());

    // Both serialization formats (mnemonic and binary) are now available
    let phrase = seed.to_string(Coin::Monero);
    assert!(!phrase.is_empty(), "to_string() still works");
}

// Language auto-detection
#[test]
fn gap3_language_auto_detection_exists() {
    let phrase = english_seed_phrase();

    // from_string_auto() detects the language automatically:
    let (seed, detected_lang) = Polyseed::from_string_auto(phrase.clone(), Coin::Monero, 0).unwrap();
    assert_eq!(detected_lang, Language::English, "Auto-detection should find English");

    // The result should match explicit from_string():
    let explicit_seed = Polyseed::from_string(Language::English, phrase.clone(), Coin::Monero, 0).unwrap();
    assert_eq!(seed, explicit_seed, "Auto-detected seed should match explicit decode");

    // Wrong language still fails with explicit from_string():
    let result_wrong = Polyseed::from_string(Language::Spanish, phrase.clone(), Coin::Monero, 0);
    assert!(result_wrong.is_err(), "Wrong language still fails with explicit from_string()");
}

// Multi-coin support
#[test]
fn gap4_multi_coin_support_exists() {
    let seed = Polyseed::from_string(Language::English, english_seed_phrase(), Coin::Monero, 0).unwrap();

    // key() now accepts a Coin parameter:
    let key_monero = seed.key(Coin::Monero);
    let key_aeon = seed.key(Coin::Aeon);
    let key_wownero = seed.key(Coin::Wownero);

    assert_eq!(key_monero.len(), 32, "key() produces a 32-byte key");
    assert_ne!(*key_monero, *key_aeon, "Different coins produce different keys");
    assert_ne!(*key_monero, *key_wownero, "Different coins produce different keys");

    // to_string() and from_string() also accept a Coin parameter:
    let phrase = seed.to_string(Coin::Monero);
    let seed2 = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    assert_eq!(seed, seed2, "Round-trip with Coin::Monero works");
}

// Feature flags (enabled_features parameter)

#[test]
fn gap5_no_enable_features_support() {
    let entropy = test_entropy();

    // Feature bits can now be set through from():
    let seed_feat1 = Polyseed::from(Language::English, 1, 1635768000, entropy.clone()).unwrap();
    assert_eq!(get_feature(seed_feat1.features(), 1), 1);

    let seed_feat2 = Polyseed::from(Language::English, 2, 1635768000, entropy.clone()).unwrap();
    assert_eq!(get_feature(seed_feat2.features(), 2), 2);

    let seed_feat4 = Polyseed::from(Language::English, 4, 1635768000, entropy.clone()).unwrap();
    assert_eq!(get_feature(seed_feat4.features(), 4), 4);

    // from_string rejects unknown features when enabled_features=0:
    let phrase = seed_feat1.to_string(Coin::Monero);
    let res = Polyseed::from_string(Language::English, phrase.clone(), Coin::Monero, 0);
    assert_eq!(res, Err(PolyseedError::UnsupportedFeatures));

    // from_string accepts when caller enables that feature:
    let res = Polyseed::from_string(Language::English, phrase, Coin::Monero, 1);
    assert!(res.is_ok());
}

// is_encrypted() accessor
#[test]
fn gap6_is_encrypted_accessor_exists() {
    let seed = Polyseed::from_string(Language::English, english_seed_phrase(), Coin::Monero, 0).unwrap();

    // is_encrypted() now works:
    assert!(!seed.is_encrypted(), "An unencrypted seed should return false");
    assert_eq!(seed.features(), 0, "This test seed has features=0 (unencrypted)");
}

// NFC output composition (Japanese/Korean ideographic spaces)

#[test]
fn gap7_no_nfc_output_composition() {
    let ja_seed = Polyseed::from(
        Language::Japanese,
        0,
        JAPANESE_BIRTHDAY,
        japanese_entropy(),
    )
    .unwrap();

    let output = ja_seed.to_string(Coin::Monero);

    let ideographic_space = '\u{3000}';
    let uses_ascii_space = output.contains(' ');
    let uses_ideographic_space = output.contains(ideographic_space);

    // Now uses ideographic spaces for Japanese
    assert!(
        !uses_ascii_space,
        "Rust to_string() no longer uses ASCII spaces for Japanese"
    );
    assert!(
        uses_ideographic_space,
        "Rust to_string() now uses ideographic spaces for Japanese"
    );

    // Split by ideographic space to count words
    let word_count: usize = output.split(ideographic_space).count();
    assert_eq!(word_count, 16, "Japanese seed has 16 words");

    // NFC composition means no combining marks
    let has_combining_marks = output.chars().any(|c| {
        c == '\u{3099}' || c == '\u{309A}'
    });
    assert!(
        !has_combining_marks,
        "Rust output is NFC-composed, no combining marks"
    );

}

// Round-trip fidelity with C reference

#[test]
fn gap_roundtrip_differences_with_c_reference() {
    let ja_seed = Polyseed::from(
        Language::Japanese,
        0,
        JAPANESE_BIRTHDAY,
        japanese_entropy(),
    )
    .unwrap();

    let rust_output = ja_seed.to_string(Coin::Monero);

    // Now uses ideographic spaces and NFC composition, matching C reference
    assert!(
        rust_output.contains('\u{3000}'),
        "Rust output now contains ideographic spaces"
    );
    assert!(
        !rust_output.contains(' '),
        "Rust output no longer uses ASCII spaces for Japanese"
    );

    let has_nfd_marks = rust_output.chars().any(|c| c == '\u{3099}' || c == '\u{309A}');
    assert!(
        !has_nfd_marks,
        "Rust output is NFC-composed, no combining marks"
    );

    // English round-trip IS identical (ASCII only, no Unicode issues)
    let en_phrase = english_seed_phrase();
    let en_seed = Polyseed::from_string(Language::English, en_phrase.clone(), Coin::Monero, 0).unwrap();
    let en_output = en_seed.to_string(Coin::Monero);
    assert_eq!(
        *en_output, *en_phrase,
        "English round-trip IS identical (ASCII only, no Unicode issues)"
    );

    // Round-trip for Japanese via from_string + to_string
    let ja_phrase = rust_output.clone();
    let ja_seed2 = Polyseed::from_string(
        Language::Japanese,
        ja_phrase.clone(),
        Coin::Monero,
        0,
    )
    .unwrap();
    let ja_output2 = ja_seed2.to_string(Coin::Monero);
    assert_eq!(
        *ja_output2, *ja_phrase,
        "Japanese round-trip with ideographic-space NFC phrases IS consistent"
    );
}

// Public API inventory

#[test]
fn summary_api_inventory() {
    // Verify the API shape by exercising every public method:
    let seed = Polyseed::from_string(Language::English, english_seed_phrase(), Coin::Monero, 0).unwrap();
    let _birthday: u64 = seed.birthday();
    let _features: u8 = seed.features();
    let _is_encrypted: bool = seed.is_encrypted();
    let _entropy: &Zeroizing<[u8; 32]> = seed.entropy();
    let _key: Zeroizing<[u8; 32]> = seed.key(Coin::Monero);
    let _phrase: Zeroizing<String> = seed.to_string(Coin::Monero);
    let (_auto_seed, _auto_lang): (Polyseed, Language) =
        Polyseed::from_string_auto(english_seed_phrase(), Coin::Monero, 0).unwrap();

    // Verify error types exist:
    let _: PolyseedError = PolyseedError::InvalidSeed;
    let _: PolyseedError = PolyseedError::InvalidEntropy;
    let _: PolyseedError = PolyseedError::InvalidChecksum;
    let _: PolyseedError = PolyseedError::UnsupportedFeatures;
    let _: PolyseedError = PolyseedError::MultipleLanguagesMatch;

    // Verify Coin enum variants:
    let _coins = [Coin::Monero, Coin::Aeon, Coin::Wownero];

    // Verify Language enum variants:
    let _langs = [
        Language::English,
        Language::Spanish,
        Language::French,
        Language::Italian,
        Language::Japanese,
        Language::Korean,
        Language::Czech,
        Language::Portuguese,
        Language::ChineseSimplified,
        Language::ChineseTraditional,
    ];

}
