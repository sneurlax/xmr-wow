// Vendored upstream test code; lint suppressed
#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::manual_div_ceil,
    clippy::identity_op,
    clippy::erasing_op,
    dead_code,
    unused_variables
)]
//! Encryption verification against C reference.

use polyseed::{Coin, Language, Polyseed};
use zeroize::Zeroizing;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

// Constants mirrored from the C reference and Rust lib.rs
const SECRET_BITS: usize = 150;
const BITS_PER_BYTE: usize = 8;
const SECRET_SIZE: usize = SECRET_BITS.div_ceil(BITS_PER_BYTE); // 19
const CLEAR_BITS: usize = (SECRET_SIZE * BITS_PER_BYTE) - SECRET_BITS; // 2
#[allow(clippy::cast_possible_truncation)]
const LAST_BYTE_SECRET_BITS_MASK: u8 = ((1 << (BITS_PER_BYTE - CLEAR_BITS)) - 1) as u8; // 0x3F
const ENCRYPTED_MASK: u8 = 1 << 4; // 0x10
const POLYSEED_CRYPT_ITERATIONS: u32 = 10000;

// Verify constant values match the C reference
#[test]
fn verify_constants_match_c_reference() {
    // SECRET_SIZE in C: (150 + 8 - 1) / 8 = 19
    assert_eq!(SECRET_SIZE, 19, "SECRET_SIZE must be 19");

    // CLEAR_BITS in C: 19 * 8 - 150 = 2
    assert_eq!(CLEAR_BITS, 2, "CLEAR_BITS must be 2");

    // CLEAR_MASK in C: ~(uint8_t)(((1u << 2) - 1) << (8 - 2))
    //   = ~(uint8_t)((3) << 6) = ~(uint8_t)(0xC0) = 0x3F
    assert_eq!(LAST_BYTE_SECRET_BITS_MASK, 0x3F, "CLEAR_MASK must be 0x3F");

    // ENCRYPTED_MASK in C: 16 = 0x10
    assert_eq!(ENCRYPTED_MASK, 0x10, "ENCRYPTED_MASK must be 0x10");

    // KDF_NUM_ITERATIONS in C: 10000
    assert_eq!(
        POLYSEED_CRYPT_ITERATIONS, 10000,
        "KDF iterations must be 10000"
    );
}

// Verify salt construction matches C reference exactly.
// Final salt: "POLYSEED mask" + 0x00 + 0xFF + 0xFF
#[test]
fn verify_encryption_salt_construction() {
    let mut salt = [0u8; 16];
    salt[..13].copy_from_slice(b"POLYSEED mask");
    // salt[13] stays 0x00 -- matches C's null terminator
    salt[14] = 0xFF;
    salt[15] = 0xFF;

    // Expected: "POLYSEED mask" (hex: 504f4c5953454544206d61736b) + 00 + ff + ff
    let expected_hex = "504f4c5953454544206d61736b00ffff";
    assert_eq!(
        hex::encode(&salt),
        expected_hex,
        "Encryption salt must match C reference byte-for-byte"
    );

    // Cross-check individual bytes
    assert_eq!(salt[0], b'P');
    assert_eq!(salt[1], b'O');
    assert_eq!(salt[2], b'L');
    assert_eq!(salt[3], b'Y');
    assert_eq!(salt[4], b'S');
    assert_eq!(salt[5], b'E');
    assert_eq!(salt[6], b'E');
    assert_eq!(salt[7], b'D');
    assert_eq!(salt[8], b' ');
    assert_eq!(salt[9], b'm');
    assert_eq!(salt[10], b'a');
    assert_eq!(salt[11], b's');
    assert_eq!(salt[12], b'k');
    assert_eq!(salt[13], 0x00);
    assert_eq!(salt[14], 0xFF);
    assert_eq!(salt[15], 0xFF);

    // Verify the C test also confirms this salt
    // From tests.c pbkdf2_dummy3: assert(equals_hex(salt, "504f4c5953454544206d61736b00ffff"));
    // This matches.
}

// Verify PBKDF2 mask derivation. The C test uses a mock PBKDF2 (g_test_mask
// is a fixture, not real output). The real PBKDF2-HMAC-SHA256 output is
// 886777de23641e21a0fd252d37a9d06b2d87fd1f3c8c001624e909b31f2c9be5.
#[test]
fn verify_pbkdf2_mask_derivation() {
    let password = b"password";

    let mut salt = [0u8; 16];
    salt[..13].copy_from_slice(b"POLYSEED mask");
    salt[14] = 0xFF;
    salt[15] = 0xFF;

    let mut mask = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, POLYSEED_CRYPT_ITERATIONS, &mut mask);

    let mask_hex = hex::encode(&mask);

    // The real PBKDF2-HMAC-SHA256 output, verified with Python's hashlib
    let expected_real_mask = "886777de23641e21a0fd252d37a9d06b2d87fd1f3c8c001624e909b31f2c9be5";

    assert_eq!(
        mask_hex, expected_real_mask,
        "PBKDF2-HMAC-SHA256 must produce the correct standardized output"
    );

    // The C test's g_test_mask is a dummy value, not real PBKDF2 output
    let c_dummy_mask = "544a8895ffc0451c9b8e281e182d0d73637d1bd7cb6eed8f8435b3138c0cf04e";
    assert_ne!(
        mask_hex, c_dummy_mask,
        "Our real PBKDF2 should differ from the C test's dummy value"
    );
}

// Verify the XOR loop operates on exactly SECRET_SIZE (19) bytes,
// then clears the top 2 bits of byte 18.
#[test]
fn verify_xor_loop_range() {
    // Create a seed, encrypt it, and verify only the first 19 bytes changed
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();
    let original_entropy = original.entropy().clone();

    let mut encrypted = original.clone();
    encrypted.crypt("testpassword");

    // Bytes 0..19 should (generally) differ after encryption
    // Bytes 19..32 should remain zero
    for i in SECRET_SIZE..32 {
        assert_eq!(
            encrypted.entropy()[i],
            0,
            "Byte {} (beyond SECRET_SIZE) must remain zero after encryption",
            i
        );
    }

    // Verify the last secret byte has its top 2 bits cleared
    assert_eq!(
        encrypted.entropy()[SECRET_SIZE - 1] & !LAST_BYTE_SECRET_BITS_MASK,
        0,
        "Top 2 bits of byte 18 must be cleared after encryption"
    );

    // Verify the original also had top 2 bits cleared
    assert_eq!(
        original_entropy[SECRET_SIZE - 1] & !LAST_BYTE_SECRET_BITS_MASK,
        0,
        "Original seed should also have top 2 bits cleared"
    );
}

// Verify feature toggle (ENCRYPTED_MASK = 0x10)
#[test]
fn verify_feature_toggle() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    assert_eq!(
        original.features() & ENCRYPTED_MASK,
        0,
        "Original should not have ENCRYPTED bit"
    );
    assert!(!original.is_encrypted());

    let mut seed = original.clone();
    seed.crypt("password");
    assert_eq!(
        seed.features() & ENCRYPTED_MASK,
        ENCRYPTED_MASK,
        "After crypt, ENCRYPTED bit must be set"
    );
    assert!(seed.is_encrypted());
    // features should be exactly 0x10 (0 XOR 0x10)
    assert_eq!(
        seed.features(),
        0x10,
        "Features should be exactly 0x10 after encrypting a features=0 seed"
    );

    seed.crypt("password");
    assert_eq!(
        seed.features() & ENCRYPTED_MASK,
        0,
        "After second crypt, ENCRYPTED bit must be cleared"
    );
    assert!(!seed.is_encrypted());
    assert_eq!(
        seed.features(),
        0,
        "Features should be back to 0 after decrypt"
    );
}

// Verify checksum recalculation after encryption
#[test]
fn verify_checksum_recalculation() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut encrypted = original.clone();
    encrypted.crypt("password");

    // After encryption, the seed should still have a valid checksum.
    // We verify this by storing and loading (which validates the checksum).
    let storage = encrypted.store();
    let loaded = Polyseed::load(&storage, Language::English, 0);
    assert!(
        loaded.is_ok(),
        "Encrypted seed should store/load successfully (checksum valid)"
    );

    let loaded = loaded.unwrap();
    assert_eq!(loaded, encrypted, "Loaded encrypted seed should match");
    assert!(
        loaded.is_encrypted(),
        "Loaded seed should still be encrypted"
    );
}

// Full round-trip: encrypt then decrypt == original (self-inverse property)
#[test]
fn verify_full_roundtrip_self_inverse() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut seed = original.clone();

    // Encrypt
    seed.crypt("my_secret_password");
    assert!(seed.is_encrypted());
    assert_ne!(
        *seed.entropy(),
        *original.entropy(),
        "Encrypted entropy should differ"
    );

    // Decrypt (second application is the inverse)
    seed.crypt("my_secret_password");
    assert!(!seed.is_encrypted());
    assert_eq!(
        *seed.entropy(),
        *original.entropy(),
        "Decrypted entropy should match original"
    );
    assert_eq!(
        seed, original,
        "Decrypted seed should be identical to original"
    );
}

// Verify encrypted seed can encode/decode through mnemonic phrases
#[test]
fn verify_encrypted_seed_phrase_roundtrip() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();
    let original_key = original.key(Coin::Monero);

    // Encrypt
    let mut encrypted = original.clone();
    encrypted.crypt("password");

    // Encode encrypted seed to phrase
    let encrypted_phrase = encrypted.to_string(Coin::Monero);

    // Decode the encrypted phrase
    let decoded = Polyseed::from_string(Language::English, encrypted_phrase, Coin::Monero, 0);
    assert!(
        decoded.is_ok(),
        "Encrypted seed phrase should decode successfully"
    );

    let mut decoded = decoded.unwrap();
    assert!(decoded.is_encrypted(), "Decoded seed should be encrypted");

    // Decrypt
    decoded.crypt("password");
    assert!(!decoded.is_encrypted(), "Should be decrypted after crypt");

    // Verify key matches original
    let decrypted_key = decoded.key(Coin::Monero);
    assert_eq!(
        *decrypted_key, *original_key,
        "Decrypted key should match original"
    );
    assert_eq!(decoded, original, "Decrypted seed should match original");
}

// Verify encrypted seed can be stored/loaded
#[test]
fn verify_encrypted_seed_store_load_roundtrip() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut encrypted = original.clone();
    encrypted.crypt("password");

    // Store
    let storage = encrypted.store();

    // Verify the storage contains the encrypted features
    // Byte 8-9 contain (features << 10) | birthday as LE u16
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let stored_features = v1 >> 10;
    assert_eq!(
        stored_features & u16::from(ENCRYPTED_MASK),
        u16::from(ENCRYPTED_MASK),
        "Stored features should have ENCRYPTED bit set"
    );

    // Load
    let mut loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert!(loaded.is_encrypted(), "Loaded seed should be encrypted");
    assert_eq!(loaded, encrypted, "Loaded should match encrypted");

    // Decrypt the loaded seed
    loaded.crypt("password");
    assert!(!loaded.is_encrypted());
    assert_eq!(
        loaded, original,
        "Decrypted loaded seed should match original"
    );
}

// Verify NFKD normalization of password
#[test]
fn verify_password_nfkd_normalization() {
    use unicode_normalization::UnicodeNormalization;

    // ASCII password: NFKD is identity
    let password = "password";
    let nfkd: String = password.nfkd().collect();
    assert_eq!(nfkd, "password", "NFKD of ASCII should be identity");
    assert_eq!(nfkd.as_bytes(), b"password");

    // Unicode password with precomposed character
    let password_nfc = "p\u{00E4}ssword"; // pa-umlaut-ssword (NFC)
    let nfkd_nfc: String = password_nfc.nfkd().collect();

    let password_nfd = "pa\u{0308}ssword"; // p + a + combining diaeresis + ssword (NFD)
    let nfkd_nfd: String = password_nfd.nfkd().collect();

    assert_eq!(
        nfkd_nfc, nfkd_nfd,
        "NFKD of NFC and NFD forms should produce the same result"
    );

    // Verify round-trip: encrypt with NFC password, decrypt with NFD password
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut encrypted = original.clone();
    encrypted.crypt(password_nfc);

    let mut decrypted = encrypted.clone();
    decrypted.crypt(password_nfd);

    assert_eq!(
        decrypted, original,
        "Encrypting with NFC and decrypting with NFD should round-trip correctly"
    );
}

// Verify wrong password does NOT decrypt correctly
#[test]
fn verify_wrong_password_fails() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut encrypted = original.clone();
    encrypted.crypt("correct_password");

    let mut wrong_decrypt = encrypted.clone();
    wrong_decrypt.crypt("wrong_password");

    // The features bit will be cleared (toggled twice), but the entropy will
    // be wrong because the XOR masks don't cancel out
    assert!(
        !wrong_decrypt.is_encrypted(),
        "Features toggle regardless of password"
    );
    assert_ne!(
        *wrong_decrypt.entropy(),
        *original.entropy(),
        "Wrong password should produce different entropy"
    );
    assert_ne!(
        wrong_decrypt, original,
        "Wrong password should not recover original seed"
    );
}

// Verify C seed3 encryption math (manual XOR, since Rust doesn't support features=1)
#[test]
fn verify_c_seed3_encryption_math() {
    let entropy_hex = "67b936dfa4da6ae8d3b3cdb3b937f4027b0e3b";
    let mask_hex = "544a8895ffc0451c9b8e281e182d0d73637d1bd7cb6eed8f8435b3138c0cf04e";

    let entropy_bytes = hex::decode(entropy_hex).unwrap();
    let mask_bytes = hex::decode(mask_hex).unwrap();

    assert_eq!(entropy_bytes.len(), 19, "Entropy should be 19 bytes");
    assert_eq!(mask_bytes.len(), 32, "Mask should be 32 bytes");

    // Compute XOR of first 19 bytes
    let mut encrypted = [0u8; 19];
    for i in 0..19 {
        encrypted[i] = entropy_bytes[i] ^ mask_bytes[i];
    }
    // Clear top 2 bits of last byte
    encrypted[18] &= LAST_BYTE_SECRET_BITS_MASK;

    // Verify last byte is within 6 bits
    assert_eq!(
        encrypted[18] & !LAST_BYTE_SECRET_BITS_MASK,
        0,
        "Top 2 bits of encrypted byte 18 must be cleared"
    );

    // Verify the XOR is reversible
    let mut decrypted = encrypted;
    for i in 0..19 {
        decrypted[i] ^= mask_bytes[i];
    }
    decrypted[18] &= LAST_BYTE_SECRET_BITS_MASK;

    // NOTE: This is only exactly reversible if the original entropy[18] had
    // its top 2 bits clear, which it does (0x3b & 0x3F = 0x3b).
    assert_eq!(
        hex::encode(&decrypted),
        entropy_hex,
        "XOR operation should be reversible"
    );

    // Verify that entropy[18] (0x3b) already had top 2 bits clear
    assert_eq!(
        entropy_bytes[18] & !LAST_BYTE_SECRET_BITS_MASK,
        0,
        "Original entropy byte 18 should have top 2 bits clear"
    );

    // Verify features toggle
    let original_features: u8 = 1; // FEATURE_FOO
    let encrypted_features = original_features ^ ENCRYPTED_MASK;
    assert_eq!(
        encrypted_features, 0x11,
        "features=1 XOR ENCRYPTED_MASK should be 0x11"
    );

    let decrypted_features = encrypted_features ^ ENCRYPTED_MASK;
    assert_eq!(
        decrypted_features, original_features,
        "Features toggle should be self-inverse"
    );
}

// Verify PBKDF2 inputs match the C test's assertions and the real output
#[test]
fn verify_c_test_vector_inputs_and_real_mask() {
    // Verify the inputs match what the C test asserts
    let pw = b"password";
    assert_eq!(
        hex::encode(pw),
        "70617373776f7264",
        "Password hex must match C test assertion"
    );

    let mut salt = [0u8; 16];
    salt[..13].copy_from_slice(b"POLYSEED mask");
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    assert_eq!(
        hex::encode(&salt),
        "504f4c5953454544206d61736b00ffff",
        "Salt hex must match C test assertion"
    );

    // Compute real PBKDF2
    let mut mask = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pw, &salt, 10000, &mut mask);

    // Verify against Python-verified reference output
    let real_expected = "886777de23641e21a0fd252d37a9d06b2d87fd1f3c8c001624e909b31f2c9be5";
    assert_eq!(
        hex::encode(&mask),
        real_expected,
        "PBKDF2-HMAC-SHA256 must match Python-verified output"
    );

    // Verify this differs from the C test's dummy mask
    let c_dummy = "544a8895ffc0451c9b8e281e182d0d73637d1bd7cb6eed8f8435b3138c0cf04e";
    assert_ne!(hex::encode(&mask), c_dummy);
}

// Verify full encryption with known seed (features=0), comparing manual
// PBKDF2 XOR against what crypt() produces.
#[test]
fn verify_full_encryption_known_seed() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let original_entropy = seed.entropy().clone();

    // Compute the mask ourselves
    let password = "password";
    let mut salt = [0u8; 16];
    salt[..13].copy_from_slice(b"POLYSEED mask");
    salt[14] = 0xFF;
    salt[15] = 0xFF;

    let mut expected_mask = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 10000, &mut expected_mask);

    // Manually compute expected encrypted entropy
    let mut expected_encrypted = [0u8; 32];
    for i in 0..SECRET_SIZE {
        expected_encrypted[i] = original_entropy[i] ^ expected_mask[i];
    }
    expected_encrypted[SECRET_SIZE - 1] &= LAST_BYTE_SECRET_BITS_MASK;
    // Bytes 19..32 remain 0

    // Now encrypt using crypt()
    let mut encrypted = seed.clone();
    encrypted.crypt(password);

    assert_eq!(
        encrypted.entropy().as_ref(),
        &expected_encrypted,
        "crypt() must produce the same result as manual XOR with PBKDF2 mask"
    );

    // Verify features
    assert_eq!(encrypted.features(), ENCRYPTED_MASK);

    // Verify round-trip
    let mut decrypted = encrypted;
    decrypted.crypt(password);
    assert_eq!(
        decrypted.entropy().as_ref(),
        original_entropy.as_ref(),
        "Round-trip must recover original entropy"
    );
}

// Verify RESERVED_FEATURES_MASK interaction with encryption.
// RESERVED_FEATURES_MASK = 0x1F ^ 0x10 = 0x0F.
#[test]
fn verify_features_mask_interaction() {
    const RESERVED_FEATURES_MASK: u8 = ((1u8 << 5) - 1) ^ ENCRYPTED_MASK;
    assert_eq!(RESERVED_FEATURES_MASK, 0x0F);

    // features=0 (no features): supported
    assert_eq!(0x00 & RESERVED_FEATURES_MASK, 0);

    // features=0x10 (encrypted, no user features): supported
    assert_eq!(0x10u8 & RESERVED_FEATURES_MASK, 0);

    // features=1 (FEATURE_FOO): NOT supported in Rust
    assert_ne!(0x01u8 & RESERVED_FEATURES_MASK, 0);

    // features=0x11 (encrypted + FEATURE_FOO): NOT supported in Rust
    assert_ne!(0x11u8 & RESERVED_FEATURES_MASK, 0);

    // Verify that encrypting a features=0 seed produces features=0x10,
    // which IS supported
    let seed = Polyseed::new(&mut rand_core::OsRng, Language::English);
    let mut encrypted = seed.clone();
    encrypted.crypt("pass");

    assert_eq!(encrypted.features(), 0x10);

    // The encrypted seed can be encoded and decoded
    let phrase = encrypted.to_string(Coin::Monero);
    let decoded = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0);
    assert!(
        decoded.is_ok(),
        "Encrypted seed with features=0x10 should be decodable"
    );
}

// Verify calling crypt() on an already-encrypted seed decrypts it
#[test]
fn verify_double_crypt_is_identity() {
    let seed = Polyseed::new(&mut rand_core::OsRng, Language::English);
    let original = seed.clone();

    let mut s = seed;

    // First crypt: encrypt
    s.crypt("password");
    assert!(s.is_encrypted());

    // Second crypt with same password: decrypt
    s.crypt("password");
    assert!(!s.is_encrypted());
    assert_eq!(s, original);
}

// Verify different passwords produce different results
#[test]
fn verify_different_passwords_produce_different_results() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut enc1 = original.clone();
    enc1.crypt("password1");

    let mut enc2 = original.clone();
    enc2.crypt("password2");

    assert_ne!(
        *enc1.entropy(),
        *enc2.entropy(),
        "Different passwords should produce different encrypted entropy"
    );

    // Both should decrypt back to original
    enc1.crypt("password1");
    enc2.crypt("password2");
    assert_eq!(enc1, original);
    assert_eq!(enc2, original);
}

// Verify empty password works (edge case)
#[test]
fn verify_empty_password() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut encrypted = original.clone();
    encrypted.crypt("");
    assert!(encrypted.is_encrypted());

    // Even with empty password, encryption should change the entropy
    // (because PBKDF2 with empty password still produces a non-zero mask)
    assert_ne!(*encrypted.entropy(), *original.entropy());

    // Round-trip with empty password
    encrypted.crypt("");
    assert_eq!(encrypted, original);
}

// Verify crypt() works with all coins
#[test]
fn verify_crypt_coin_independence() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Encrypt/decrypt cycle should work regardless of which coin is used
    // for encoding/decoding, because crypt() does not depend on the coin.
    let mut encrypted = original.clone();
    encrypted.crypt("password");

    // Encode with different coins
    let phrase_monero = encrypted.to_string(Coin::Monero);
    let phrase_aeon = encrypted.to_string(Coin::Aeon);
    let phrase_wownero = encrypted.to_string(Coin::Wownero);

    // Decode back with the correct coin
    let dec_monero =
        Polyseed::from_string(Language::English, phrase_monero, Coin::Monero, 0).unwrap();
    let dec_aeon = Polyseed::from_string(Language::English, phrase_aeon, Coin::Aeon, 0).unwrap();
    let dec_wownero =
        Polyseed::from_string(Language::English, phrase_wownero, Coin::Wownero, 0).unwrap();

    assert_eq!(dec_monero, encrypted);
    assert_eq!(dec_aeon, encrypted);
    assert_eq!(dec_wownero, encrypted);

    // Decrypt all three - should all recover the original
    let mut d1 = dec_monero;
    let mut d2 = dec_aeon;
    let mut d3 = dec_wownero;
    d1.crypt("password");
    d2.crypt("password");
    d3.crypt("password");
    assert_eq!(d1, original);
    assert_eq!(d2, original);
    assert_eq!(d3, original);
}

// Verify auto-detection works with encrypted seeds
#[test]
fn verify_auto_detection_with_encrypted_seed() {
    let seed_str = "raven tail swear infant grief assist regular lamp \
        duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(seed_str.into()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let mut encrypted = original.clone();
    encrypted.crypt("password");

    let phrase = encrypted.to_string(Coin::Monero);
    let (auto_decoded, lang) = Polyseed::from_string_auto(phrase, Coin::Monero, 0).unwrap();

    assert_eq!(lang, Language::English);
    assert!(auto_decoded.is_encrypted());
    assert_eq!(auto_decoded, encrypted);
}
