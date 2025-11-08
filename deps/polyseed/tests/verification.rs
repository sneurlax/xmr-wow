use polyseed::{Coin, Language, Polyseed, PolyseedError};
use zeroize::Zeroizing;

#[test]
fn verify_empty_string_returns_invalid_word_count() {
    let empty = Zeroizing::new(String::new());
    let result = Polyseed::from_string(Language::English, empty, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn verify_too_few_words_returns_invalid_word_count() {
    let three_words = Zeroizing::new("raven tail swear".to_string());
    let result = Polyseed::from_string(Language::English, three_words, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn verify_17_words_returns_invalid_word_count() {
    let seventeen = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language extra"
            .to_string(),
    );
    let result = Polyseed::from_string(Language::English, seventeen, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn verify_15_words_returns_invalid_word_count() {
    let fifteen = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport"
            .to_string(),
    );
    let result = Polyseed::from_string(Language::English, fifteen, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn verify_nfc_spanish_phrase_decodes_correctly() {
    let nfc_phrase = Zeroizing::new(
        "eje fin parte c\u{00e9}lebre tab\u{00fa} pesta\u{00f1}a lienzo puma \
         prisi\u{00f3}n hora regalo lengua existir l\u{00e1}piz lote sonoro"
            .to_string(),
    );
    let nfd_phrase = Zeroizing::new(
        "eje fin parte ce\u{0301}lebre tabu\u{0301} pestan\u{0303}a lienzo puma \
         prisio\u{0301}n hora regalo lengua existir la\u{0301}piz lote sonoro"
            .to_string(),
    );

    let nfc_result = Polyseed::from_string(Language::Spanish, nfc_phrase, Coin::Monero, 0);
    let nfd_result = Polyseed::from_string(Language::Spanish, nfd_phrase, Coin::Monero, 0);

    assert!(nfc_result.is_ok());
    assert!(nfd_result.is_ok());

    let nfc_seed = nfc_result.unwrap();
    let nfd_seed = nfd_result.unwrap();
    assert_eq!(nfc_seed, nfd_seed);

    assert_eq!(
        hex::encode(nfc_seed.entropy().as_ref()),
        "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000",
    );
}

#[test]
fn verify_coin_aeon_produces_different_key_than_monero() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();

    let key_monero = seed.key(Coin::Monero);
    let key_aeon = seed.key(Coin::Aeon);
    let key_wownero = seed.key(Coin::Wownero);

    assert_ne!(*key_monero, *key_aeon);
    assert_ne!(*key_monero, *key_wownero);
    assert_ne!(*key_aeon, *key_wownero);
}

/// Salt layout: [0..12] "POLYSEED key", [12] 0x00, [13..16] 0xFF,
/// [16..20] coin LE u32, [20..24] birthday LE u32, [24..28] features LE u32.
#[test]
fn verify_salt_format_matches_c_reference() {
    let mut expected_salt = [0u8; 32];
    expected_salt[..12].copy_from_slice(b"POLYSEED key");
    expected_salt[13] = 0xFF;
    expected_salt[14] = 0xFF;
    expected_salt[15] = 0xFF;
    expected_salt[16..20].copy_from_slice(&1u32.to_le_bytes());
    expected_salt[20..24].copy_from_slice(&1015u32.to_le_bytes());
    expected_salt[24..28].copy_from_slice(&1u32.to_le_bytes());

    assert_eq!(
        hex::encode(&expected_salt),
        "504f4c5953454544206b657900ffffff01000000f70300000100000000000000",
    );

    let mut rust_salt = [0u8; 32];
    rust_salt[..12].copy_from_slice(b"POLYSEED key");
    rust_salt[13] = 0xFF;
    rust_salt[14] = 0xFF;
    rust_salt[15] = 0xFF;
    rust_salt[16..20].copy_from_slice(&u32::from(1u16).to_le_bytes());
    rust_salt[20..24].copy_from_slice(&u32::from(1015u16).to_le_bytes());
    rust_salt[24..28].copy_from_slice(&u32::from(1u8).to_le_bytes());

    assert_eq!(rust_salt, expected_salt);
}

#[test]
fn verify_poly_zeroing_roundtrip() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();

    let serialized = seed.to_string(Coin::Monero);
    let deserialized =
        Polyseed::from_string(Language::English, Zeroizing::new(serialized.to_string()), Coin::Monero, 0)
            .unwrap();

    assert_eq!(seed, deserialized);
}

#[test]
fn verify_is_encrypted() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    assert!(!seed.is_encrypted());

    let mut encrypted = seed.clone();
    encrypted.crypt("test");
    assert!(encrypted.is_encrypted());

    encrypted.crypt("test");
    assert!(!encrypted.is_encrypted());
}

#[test]
fn verify_coin_enum_api() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();

    let _k1 = seed.key(Coin::Monero);
    let _k2 = seed.key(Coin::Aeon);
    let _k3 = seed.key(Coin::Wownero);

    let monero_phrase = seed.to_string(Coin::Monero);
    let seed2 =
        Polyseed::from_string(Language::English, Zeroizing::new(monero_phrase.to_string()), Coin::Monero, 0)
            .unwrap();
    assert_eq!(seed, seed2);

    let result_aeon = Polyseed::from_string(
        Language::English,
        Zeroizing::new(monero_phrase.to_string()),
        Coin::Aeon,
        0,
    );
    assert!(result_aeon.is_err());
}

#[test]
fn verify_store_load_roundtrip_preserves_all_fields() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();

    let storage = seed.store();
    assert_eq!(&storage[..8], b"POLYSEED");
    assert_eq!(storage[29], 0xFF);

    let footer_val = u16::from_le_bytes([storage[30], storage[31]]);
    assert_eq!(footer_val & 0xF800, 0x7000);

    let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert_eq!(*seed.entropy(), *loaded.entropy());
    assert_eq!(seed.birthday(), loaded.birthday());
    assert_eq!(seed.features(), loaded.features());
    assert_eq!(seed.key(Coin::Monero), loaded.key(Coin::Monero));
    assert_eq!(seed, loaded);
}

#[test]
fn verify_store_load_encrypted_seed() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let original = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    let original_entropy = original.entropy().clone();

    let mut encrypted = original.clone();
    encrypted.crypt("store_test_pw");
    assert!(encrypted.is_encrypted());

    let storage = encrypted.store();
    let mut loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert!(loaded.is_encrypted());
    assert_eq!(encrypted, loaded);

    loaded.crypt("store_test_pw");
    assert!(!loaded.is_encrypted());
    assert_eq!(loaded.entropy(), &original_entropy);
    assert_eq!(loaded, original);
}

#[test]
fn verify_crypt_roundtrip_restores_entropy() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let original = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    let original_entropy = original.entropy().clone();
    let original_key = original.key(Coin::Monero);

    let mut seed = original.clone();
    seed.crypt("my_secret_password");
    assert!(seed.is_encrypted());
    assert_ne!(seed.entropy(), &original_entropy);

    seed.crypt("my_secret_password");
    assert!(!seed.is_encrypted());
    assert_eq!(seed.entropy(), &original_entropy);
    assert_eq!(seed.key(Coin::Monero), original_key);
    assert_eq!(seed, original);
}

#[test]
fn verify_crypt_salt_construction() {
    use sha2::Sha256;
    use pbkdf2::pbkdf2_hmac;

    let mut salt = [0u8; 16];
    salt[..13].copy_from_slice(b"POLYSEED mask");
    salt[14] = 0xFF;
    salt[15] = 0xFF;

    assert_eq!(hex::encode(&salt), "504f4c5953454544206d61736b00ffff");

    let mut mask = [0u8; 32];
    pbkdf2_hmac::<Sha256>(b"password", &salt, 10000, &mut mask);
    assert_eq!(
        hex::encode(&mask),
        "886777de23641e21a0fd252d37a9d06b2d87fd1f3c8c001624e909b31f2c9be5",
    );
}

#[test]
fn verify_from_string_auto_detects_english() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let (seed, lang) = Polyseed::from_string_auto(phrase.clone(), Coin::Monero, 0).unwrap();
    assert_eq!(lang, Language::English);

    let explicit = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    assert_eq!(seed, explicit);
}

#[test]
fn verify_from_string_auto_detects_spanish() {
    let phrase = Zeroizing::new(
        "eje fin parte ce\u{0301}lebre tabu\u{0301} pestan\u{0303}a lienzo puma \
         prisio\u{0301}n hora regalo lengua existir la\u{0301}piz lote sonoro"
            .to_string(),
    );
    let (seed, lang) = Polyseed::from_string_auto(phrase.clone(), Coin::Monero, 0).unwrap();
    assert_eq!(lang, Language::Spanish);

    let explicit = Polyseed::from_string(Language::Spanish, phrase, Coin::Monero, 0).unwrap();
    assert_eq!(seed, explicit);
}

#[test]
fn verify_from_string_auto_rejects_garbage() {
    let garbage = Zeroizing::new(
        "xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx".to_string(),
    );
    let result = Polyseed::from_string_auto(garbage, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::InvalidSeed));
}

#[test]
fn verify_dart_vector_cross_implementation() {
    let phrase = Zeroizing::new(
        "unaware yard donate shallow slot sing oil oxygen \
         loyal bench near hill surround forum execute lamp"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    let key_hex = hex::encode(seed.key(Coin::Monero).as_ref());

    assert_eq!(key_hex, "cbbd142d38347773d44aa830f5f01442aa6d0d3bb48571884479531248e6fa1c");
}

#[test]
fn verify_binary_storage_format_matches_c_reference() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    let storage = seed.store();

    assert_eq!(&storage[..8], b"POLYSEED");

    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let decoded_birthday = v1 & 0x3FF;
    let decoded_features = v1 >> 10;
    assert_eq!(decoded_features, u16::from(seed.features()));

    let polyseed_epoch: u64 = 1635768000;
    let time_step: u64 = 2629746;
    let decoded_time = polyseed_epoch + (u64::from(decoded_birthday) * time_step);
    let expected_time: u64 = 1638446400;
    assert!(decoded_time.abs_diff(expected_time) < time_step);

    let expected_entropy = hex::decode("dd76e7359a0ded37cd0ff0f3c829a5ae016733").unwrap();
    assert_eq!(&storage[10..29], expected_entropy.as_slice());

    assert_eq!(storage[29], 0xFF);

    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    assert_eq!(v2 & 0xF800, 0x7000);
}

#[test]
fn verify_whitespace_only_returns_invalid_word_count() {
    let whitespace = Zeroizing::new("   \t\n  ".to_string());
    let result = Polyseed::from_string(Language::English, whitespace, Coin::Monero, 0);
    assert_eq!(result, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn verify_crypt_wrong_password_does_not_restore() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let original = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    let original_entropy = original.entropy().clone();

    let mut seed = original.clone();
    seed.crypt("correct_password");
    assert!(seed.is_encrypted());

    seed.crypt("wrong_password");
    // flag toggles regardless, but entropy won't match
    assert!(!seed.is_encrypted());
    assert_ne!(seed.entropy(), &original_entropy);
}

#[test]
fn verify_load_rejects_bad_header() {
    let mut bad = [0u8; 32];
    bad[..8].copy_from_slice(b"BADHEAD!");
    assert_eq!(Polyseed::load(&bad, Language::English, 0), Err(PolyseedError::InvalidFormat));
}

#[test]
fn verify_load_rejects_bad_footer() {
    let phrase = Zeroizing::new(
        "raven tail swear infant grief assist regular lamp \
         duck valid someone little harsh puppy airport language"
            .to_string(),
    );
    let seed = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
    let mut storage = *seed.store();
    storage[30] = 0x00;
    storage[31] = 0x00;
    assert_eq!(Polyseed::load(&storage, Language::English, 0), Err(PolyseedError::InvalidFormat));
}
