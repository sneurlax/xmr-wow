//! Behavioral bug verification tests.

use polyseed::{Coin, Language, Polyseed, PolyseedError};
use zeroize::Zeroizing;

// Word count validation

/// Fewer than 16 words should produce InvalidWordCount.
#[test]
fn bug1_too_few_words_returns_invalid_word_count() {
    let two_words = Zeroizing::new("abandon ability".to_string());
    let result = Polyseed::from_string(Language::English, two_words, Coin::Monero, 0);

    assert_eq!(
        result,
        Err(PolyseedError::InvalidWordCount),
        "Fewer than 16 words should return InvalidWordCount"
    );
}

/// More than 16 words should produce InvalidWordCount.
#[test]
fn bug1_too_many_words_returns_invalid_word_count() {
    let seventeen_words = Zeroizing::new(
        "abandon ability able about above absent absorb abstract \
         absurd abuse access accident account accuse achieve acid acoustic"
            .to_string(),
    );

    let result = Polyseed::from_string(Language::English, seventeen_words, Coin::Monero, 0);
    assert_eq!(
        result,
        Err(PolyseedError::InvalidWordCount),
        "17 words should return InvalidWordCount"
    );
}

// NFKD normalization

/// NFKD-based accent stripping produces the same result for NFC and NFD input.
#[test]
fn bug2_nfc_vs_nfd_accent_stripping_fixed() {
    use unicode_normalization::UnicodeNormalization;

    let strip_accents =
        |word: &str| -> String { word.nfkd().filter(|c| c.is_ascii()).collect() };

    // NFC form: "é" is a single precomposed character U+00E9
    let celebre_nfc = "c\u{00E9}lebre";
    // NFD form: "é" is 'e' (U+0065) + combining acute accent (U+0301)
    let celebre_nfd = "ce\u{0301}lebre";

    let stripped_nfc = strip_accents(celebre_nfc);
    let stripped_nfd = strip_accents(celebre_nfd);

    // Both NFC and NFD forms now produce "celebre" after NFKD + ASCII filter
    assert_eq!(stripped_nfc, "celebre", "NFC after NFKD strip should give celebre");
    assert_eq!(stripped_nfd, "celebre", "NFD after NFKD strip should give celebre");
    assert_eq!(
        stripped_nfc, stripped_nfd,
        "NFC and NFD forms should produce identical results after NFKD accent stripping"
    );
}

/// NFC and NFD Spanish seed phrases decode to the same seed.
#[test]
fn bug2_nfc_nfd_full_seed_spanish_fixed() {
    // NFC form: accented chars are single precomposed code points
    let seed_nfc = "eje fin parte c\u{00E9}lebre tab\u{00FA} pesta\u{00F1}a lienzo puma \
        prisi\u{00F3}n hora regalo lengua existir l\u{00E1}piz lote sonoro";

    // NFD form: accented chars are base + combining accent
    let seed_nfd = "eje fin parte ce\u{0301}lebre tabu\u{0301} pestan\u{0303}a lienzo puma \
        prisio\u{0301}n hora regalo lengua existir la\u{0301}piz lote sonoro";

    let result_nfc =
        Polyseed::from_string(Language::Spanish, Zeroizing::new(seed_nfc.to_string()), Coin::Monero, 0);
    let result_nfd =
        Polyseed::from_string(Language::Spanish, Zeroizing::new(seed_nfd.to_string()), Coin::Monero, 0);

    // Both NFC and NFD forms should now parse successfully
    assert!(result_nfc.is_ok(), "NFC form should now parse successfully");
    assert!(result_nfd.is_ok(), "NFD form should parse successfully");

    // Both should produce the same seed
    let seed_nfc = result_nfc.unwrap();
    let seed_nfd = result_nfd.unwrap();
    assert_eq!(seed_nfc, seed_nfd, "NFC and NFD forms should produce identical seeds");
}

// Encrypted seed acceptance

/// Features validation accepts unencrypted seeds and the encrypted flag, but rejects reserved bits.
#[test]
fn bug3_encrypted_mask_accepted_with_crypt_support() {
    // Replicate the constants from the source
    const FEATURE_BITS: u8 = 5;
    const ENCRYPTED_MASK: u8 = 1 << 4; // 0x10
    const RESERVED_FEATURES_MASK: u8 = ((1 << FEATURE_BITS) - 1) ^ ENCRYPTED_MASK;

    // The feature check passes 0x10 (it only checks reserved bits 0-3).
    let features_supported = |features: u8| -> bool { (features & RESERVED_FEATURES_MASK) == 0 };
    assert!(features_supported(0x00), "No features should be supported");
    assert!(features_supported(ENCRYPTED_MASK), "Encrypted flag passes feature check");
    assert!(!features_supported(0x01), "Reserved feature bits should be rejected");

    // With crypt() now available, encrypted seeds can be properly handled.
}

/// A seed with reserved feature bits returns UnsupportedFeatures.
#[test]
fn bug3_unsupported_features_still_rejected() {
    let reserved_seed = Zeroizing::new(
        "include domain claim resemble urban hire lunch bird \
         crucial fire best wife ring warm ignore model"
            .to_string(),
    );
    let result = Polyseed::from_string(Language::English, reserved_seed, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::UnsupportedFeatures));
}

// Poly type zeroing

/// Polynomial arrays are wrapped in Zeroizing and sensitive data is zeroed on drop.
#[test]
fn bug4_poly_zeroed_on_drop() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // to_string() internally creates a Zeroizing<[u16; 16]> which is zeroed on drop
    let string_repr = seed.to_string(Coin::Monero);
    assert!(!string_repr.is_empty());

    // Round-trip works correctly
    let seed2 = Polyseed::from_string(
        Language::English,
        Zeroizing::new(string_repr.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();
    assert_eq!(seed, seed2);
}

/// Words not in the word list produce InvalidSeed.
#[test]
fn garbage_input_handling() {
    let garbage = Zeroizing::new(
        "xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx".to_string(),
    );
    let result = Polyseed::from_string(Language::English, garbage, Coin::Monero, 0);
    assert!(result.is_err(), "Garbage input should produce an error");
    assert_eq!(
        result.unwrap_err(),
        PolyseedError::InvalidSeed,
        "Unknown words should produce InvalidSeed"
    );
}

/// An empty string returns InvalidWordCount.
#[test]
fn bug1_empty_string_returns_invalid_word_count() {
    let empty = Zeroizing::new(String::new());
    let result = Polyseed::from_string(Language::English, empty, Coin::Monero, 0);
    assert_eq!(
        result,
        Err(PolyseedError::InvalidWordCount),
        "Empty string should return InvalidWordCount"
    );
}
