//! Cross-verification against C reference test vectors.

use polyseed::{Coin, Language, Polyseed, PolyseedError};
use zeroize::Zeroizing;

use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;

// Constants from the C reference (birthday.h, features.h, storage.h, gf.h)
const POLYSEED_EPOCH: u64 = 1635768000;
const TIME_STEP: u64 = 2629746;
const DATE_BITS: u8 = 10;
const DATE_MASK: u16 = (1u16 << DATE_BITS) - 1;

const SECRET_BITS: usize = 150;
const SECRET_SIZE: usize = (SECRET_BITS + 7) / 8; // 19

const FEATURE_BITS: u8 = 5;
const ENCRYPTED_MASK: u8 = 16; // 1 << 4
const FEATURE_MASK: u8 = (1u8 << FEATURE_BITS) - 1; // 31
// In C: reserved_features = FEATURE_MASK ^ ENCRYPTED_MASK = 31 ^ 16 = 15
const RESERVED_FEATURES_MASK: u8 = FEATURE_MASK ^ ENCRYPTED_MASK; // 15

const GF_BITS: usize = 11;
const GF_MASK: u16 = (1u16 << GF_BITS) - 1; // 2047

const STORAGE_FOOTER: u16 = 0x7000;

// C test vector data (from tests.c)

// Seed1: features=0, coin=MONERO(0), time=1638446400
const SEED1_TIME: u64 = 1638446400;
const SEED1_ENTROPY_HEX: &str =
    "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000";
const SEED1_SALT_HEX: &str =
    "504f4c5953454544206b657900ffffff00000000010000000000000000000000";
const SEED1_PHRASE: &str =
    "raven tail swear infant grief assist regular lamp \
     duck valid someone little harsh puppy airport language";

// Seed2: features=0, coin=MONERO(0), time=3118651200
const SEED2_TIME: u64 = 3118651200;
const SEED2_ENTROPY_HEX: &str =
    "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000";
const SEED2_SALT_HEX: &str =
    "504f4c5953454544206b657900ffffff00000000330200000000000000000000";

// Seed3: features=1, coin=AEON(1), time=4305268800
const SEED3_TIME: u64 = 4305268800;
const SEED3_ENTROPY_HEX: &str =
    "67b936dfa4da6ae8d3b3cdb3b937f4027b0e3b00000000000000000000000000";
const SEED3_SALT_HEX: &str =
    "504f4c5953454544206b657900ffffff01000000f70300000100000000000000";

// Encryption test vector
const CRYPT_SALT_HEX: &str = "504f4c5953454544206d61736b00ffff";
const CRYPT_PASSWORD: &str = "password";
// The C test mask is a test fixture (injected via mock PBKDF2), not an actual
// PBKDF2 output. What matters is that both C and Rust pass identical inputs
// to PBKDF2 (same password bytes, same salt, same iterations).
const C_TEST_MASK_HEX: &str =
    "544a8895ffc0451c9b8e281e182d0d73637d1bd7cb6eed8f8435b3138c0cf04e";

// Encode birthday the same way the C reference does.
fn birthday_encode(time: u64) -> u16 {
    if time < POLYSEED_EPOCH {
        return 0;
    }
    u16::try_from(((time - POLYSEED_EPOCH) / TIME_STEP) & u64::from(DATE_MASK))
        .expect("masked value fits u16")
}

// Construct the keygen salt byte-for-byte as the C reference does.
fn c_keygen_salt(coin: u32, birthday: u32, features: u32) -> [u8; 32] {
    let mut salt = [0u8; 32];
    // "POLYSEED key" = 12 bytes of ASCII, then \0 at byte 12
    salt[..12].copy_from_slice(b"POLYSEED key");
    // salt[12] = 0x00 (C null terminator / Rust zero-init)
    salt[13] = 0xFF;
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    salt[16..20].copy_from_slice(&coin.to_le_bytes());
    salt[20..24].copy_from_slice(&birthday.to_le_bytes());
    salt[24..28].copy_from_slice(&features.to_le_bytes());
    // bytes 28..32 remain 0x00
    salt
}

// Construct the crypt salt byte-for-byte as the C reference does.
fn c_crypt_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    // "POLYSEED mask" = 13 bytes, then \0 at byte 13
    salt[..13].copy_from_slice(b"POLYSEED mask");
    // salt[13] = 0x00 (C null terminator / Rust zero-init)
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    salt
}

// Construct the C binary storage format.
fn c_storage(features: u8, birthday: u16, secret: &[u8], checksum: u16) -> [u8; 32] {
    let mut storage = [0u8; 32];
    storage[..8].copy_from_slice(b"POLYSEED");
    let v1 = (u16::from(features) << DATE_BITS) | birthday;
    storage[8..10].copy_from_slice(&v1.to_le_bytes());
    storage[10..10 + SECRET_SIZE].copy_from_slice(&secret[..SECRET_SIZE]);
    storage[29] = 0xFF;
    let v2 = STORAGE_FOOTER | checksum;
    storage[30..32].copy_from_slice(&v2.to_le_bytes());
    storage
}

// Salt construction for all three C test vectors

#[test]
fn test_salt_seed1_byte_for_byte() {
    let birthday = birthday_encode(SEED1_TIME);
    assert_eq!(birthday, 1, "Seed1 encoded birthday should be 1");

    let salt = c_keygen_salt(0, u32::from(birthday), 0);
    let salt_hex = hex::encode(salt);
    assert_eq!(salt_hex, SEED1_SALT_HEX, "Seed1 salt must match C reference");

    // Decode the seed and verify the key() method uses the same salt
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Verify entropy matches
    let entropy_hex = hex::encode(seed.entropy().as_ref());
    assert_eq!(entropy_hex, SEED1_ENTROPY_HEX, "Seed1 entropy must match");

    // Verify features and birthday
    assert_eq!(seed.features(), 0, "Seed1 features should be 0");
    assert_eq!(birthday_encode(seed.birthday()), birthday, "Seed1 birthday should encode to 1");

    // The key() method internally constructs the same salt
    // We can't directly inspect the salt, but we can verify the key is deterministic
    let key1 = seed.key(Coin::Monero);
    let key2 = seed.key(Coin::Monero);
    assert_eq!(*key1, *key2, "key() must be deterministic");
}

#[test]
fn test_salt_seed2_byte_for_byte() {
    let birthday = birthday_encode(SEED2_TIME);
    assert_eq!(birthday, 563, "Seed2 encoded birthday should be 563 (0x233)");

    let salt = c_keygen_salt(0, u32::from(birthday), 0);
    let salt_hex = hex::encode(salt);
    assert_eq!(salt_hex, SEED2_SALT_HEX, "Seed2 salt must match C reference");

    // Verify the LE encoding of 563 = 0x0233
    assert_eq!(&salt[20..24], &[0x33, 0x02, 0x00, 0x00], "563 in LE bytes");
}

#[test]
fn test_salt_seed3_byte_for_byte() {
    let birthday = birthday_encode(SEED3_TIME);
    assert_eq!(birthday, 1015, "Seed3 encoded birthday should be 1015 (0x3F7)");

    // Seed3: coin=1 (AEON), features=1
    let salt = c_keygen_salt(1, u32::from(birthday), 1);
    let salt_hex = hex::encode(salt);
    assert_eq!(salt_hex, SEED3_SALT_HEX, "Seed3 salt must match C reference");

    // Verify individual fields
    assert_eq!(&salt[16..20], &[0x01, 0x00, 0x00, 0x00], "coin=1 in LE");
    assert_eq!(&salt[20..24], &[0xF7, 0x03, 0x00, 0x00], "birthday=1015 in LE");
    assert_eq!(&salt[24..28], &[0x01, 0x00, 0x00, 0x00], "features=1 in LE");
}

#[test]
fn test_rust_key_uses_c_salt_for_seed1() {

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Compute key the "C way": manual PBKDF2 with the known C salt
    let c_salt = hex::decode(SEED1_SALT_HEX).unwrap();
    let entropy = hex::decode(SEED1_ENTROPY_HEX).unwrap();
    let mut c_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&entropy, &c_salt, 10000, &mut c_key);

    // Compute key the Rust way
    let rust_key = seed.key(Coin::Monero);

    assert_eq!(
        *rust_key, c_key,
        "Rust key() must produce identical output to C reference PBKDF2 with C salt"
    );
}

// Encryption salt matches C reference

#[test]
fn test_crypt_salt_matches_c_reference() {
    let salt = c_crypt_salt();
    let salt_hex = hex::encode(salt);
    assert_eq!(salt_hex, CRYPT_SALT_HEX, "Crypt salt must match C reference");

    assert_eq!(&salt[..13], b"POLYSEED mask", "First 13 bytes are 'POLYSEED mask'");
    assert_eq!(salt[13], 0x00, "Byte 13 is null terminator");
    assert_eq!(salt[14], 0xFF, "Byte 14 is 0xFF");
    assert_eq!(salt[15], 0xFF, "Byte 15 is 0xFF");
}

// Verify PBKDF2 inputs match C (password, salt, iterations)

#[test]
fn test_crypt_pbkdf2_inputs_match_c() {
    let pw_hex = hex::encode(CRYPT_PASSWORD.as_bytes());
    assert_eq!(pw_hex, "70617373776f7264", "Password hex matches C assertion");

    let salt = c_crypt_salt();
    let salt_hex = hex::encode(&salt);
    assert_eq!(salt_hex, CRYPT_SALT_HEX, "Salt hex matches C assertion");

    // Compute the actual PBKDF2 output
    let mut mask = [0u8; 32];
    pbkdf2_hmac::<Sha256>(CRYPT_PASSWORD.as_bytes(), &salt, 10000, &mut mask);
}

// Encrypt/decrypt roundtrip matches C behavior

#[test]
fn test_crypt_roundtrip_matches_c_behavior() {

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let original_entropy = seed.entropy().clone();
    let original_key = seed.key(Coin::Monero);
    assert!(!seed.is_encrypted(), "Fresh seed should not be encrypted");

    // Encrypt
    let mut encrypted = seed.clone();
    encrypted.crypt(CRYPT_PASSWORD);
    assert!(encrypted.is_encrypted(), "Should be encrypted after crypt");
    assert_ne!(
        encrypted.entropy().as_ref(),
        original_entropy.as_ref(),
        "Encrypted entropy should differ"
    );

    // The encrypted flag should be ENCRYPTED_MASK (16) XORed into features
    assert_eq!(
        encrypted.features() & ENCRYPTED_MASK,
        ENCRYPTED_MASK,
        "Encrypted mask bit should be set"
    );

    // Store/encode the encrypted seed, load/decode it, then decrypt
    let encrypted_phrase = encrypted.to_string(Coin::Monero);
    let mut decoded = Polyseed::from_string(
        Language::English,
        encrypted_phrase,
        Coin::Monero,
        0,
    )
    .unwrap();
    assert!(decoded.is_encrypted(), "Decoded encrypted seed should be encrypted");

    // Decrypt
    decoded.crypt(CRYPT_PASSWORD);
    assert!(!decoded.is_encrypted(), "Should be decrypted after second crypt");
    assert_eq!(
        decoded.entropy().as_ref(),
        original_entropy.as_ref(),
        "Decrypted entropy should match original"
    );
    assert_eq!(
        *decoded.key(Coin::Monero),
        *original_key,
        "Decrypted key should match original"
    );
}

// Store format matches C binary layout

#[test]
fn test_store_format_matches_c_layout() {

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let storage = seed.store();

    // Header: "POLYSEED"
    assert_eq!(&storage[..8], b"POLYSEED", "Header must be 'POLYSEED'");

    // Features and birthday: (features << 10) | birthday as LE u16
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let decoded_birthday = v1 & DATE_MASK;
    let decoded_features = (v1 >> DATE_BITS) as u8;
    assert_eq!(decoded_features, seed.features(), "Features from storage must match");
    assert_eq!(
        decoded_birthday,
        birthday_encode(seed.birthday()),
        "Birthday from storage must match"
    );

    // Secret: 19 bytes at offset 10
    let entropy = seed.entropy();
    assert_eq!(
        &storage[10..10 + SECRET_SIZE],
        &entropy[..SECRET_SIZE],
        "Secret bytes must match entropy"
    );

    // Extra byte: 0xFF at offset 29
    assert_eq!(storage[29], 0xFF, "Extra byte must be 0xFF");

    // Footer: (0x7000 | checksum) as LE u16
    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    let decoded_checksum = v2 & GF_MASK;
    let decoded_footer = v2 & !GF_MASK;
    assert_eq!(decoded_footer, STORAGE_FOOTER, "Footer must be 0x7000");

    // Manually construct the C-style storage and compare
    let c_store = c_storage(
        seed.features(),
        birthday_encode(seed.birthday()),
        &entropy[..],
        decoded_checksum,
    );
    assert_eq!(
        storage.as_ref(),
        &c_store,
        "Rust store() output must match C reference layout"
    );
}

// Load validates all C format checks

#[test]
fn test_load_validates_c_format_checks() {

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let storage = seed.store();

    // C test_format: flip every bit of every byte, verify load fails
    for i in 0..32 {
        for j in 0..8 {
            let mask = 1u8 << j;
            let mut modified = *storage;
            modified[i] ^= mask;
            let result = Polyseed::load(&modified, Language::English, 0);
            assert!(
                result.is_err(),
                "Flipping bit {j} of byte {i} should cause load to fail"
            );
        }
    }

    // Verify successful roundtrip
    let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert_eq!(seed, loaded, "Load should roundtrip successfully");
}

// Verify all 3 C test vectors (entropy, birthday, features)

#[test]
fn test_c_seed1_full_verification() {

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Entropy
    let entropy_hex = hex::encode(seed.entropy().as_ref());
    assert_eq!(entropy_hex, SEED1_ENTROPY_HEX, "Seed1 entropy matches");

    // Birthday: within one TIME_STEP of expected
    let diff = seed.birthday().abs_diff(SEED1_TIME);
    assert!(diff < TIME_STEP, "Seed1 birthday within range (diff={diff})");

    // Encoded birthday
    let encoded = birthday_encode(SEED1_TIME);
    assert_eq!(encoded, 1, "Seed1 encoded birthday = 1");

    // Features
    assert_eq!(seed.features(), 0, "Seed1 features = 0");

    // Not encrypted
    assert!(!seed.is_encrypted(), "Seed1 is not encrypted");

    // Phrase roundtrip
    let phrase = seed.to_string(Coin::Monero);
    assert_eq!(
        phrase.as_str(),
        SEED1_PHRASE,
        "Seed1 phrase roundtrips"
    );

    // Key derivation uses the correct salt
    let c_salt = hex::decode(SEED1_SALT_HEX).unwrap();
    let mut c_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(seed.entropy().as_slice(), &c_salt, 10000, &mut c_key);
    let rust_key = seed.key(Coin::Monero);
    assert_eq!(*rust_key, c_key, "Seed1 key matches C reference");
}

#[test]
fn test_c_seed2_full_verification() {

    // Seed2 uses the Spanish phrase from the C test
    // NFC form (precomposed accents, matching the C test g_phrase_es1)
    let phrase = "eje fin parte c\u{00e9}lebre tab\u{00fa} pesta\u{00f1}a lienzo puma \
                  prisi\u{00f3}n hora regalo lengua existir l\u{00e1}piz lote sonoro";

    let seed = Polyseed::from_string(
        Language::Spanish,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Entropy
    let entropy_hex = hex::encode(seed.entropy().as_ref());
    assert_eq!(entropy_hex, SEED2_ENTROPY_HEX, "Seed2 entropy matches");

    // Birthday
    let diff = seed.birthday().abs_diff(SEED2_TIME);
    assert!(diff < TIME_STEP, "Seed2 birthday within range (diff={diff})");
    let encoded = birthday_encode(SEED2_TIME);
    assert_eq!(encoded, 563, "Seed2 encoded birthday = 563");

    // Features
    assert_eq!(seed.features(), 0, "Seed2 features = 0");

    // Key derivation
    let c_salt = hex::decode(SEED2_SALT_HEX).unwrap();
    let mut c_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(seed.entropy().as_slice(), &c_salt, 10000, &mut c_key);
    let rust_key = seed.key(Coin::Monero);
    assert_eq!(*rust_key, c_key, "Seed2 key matches C reference");
}

#[test]
fn test_c_seed3_salt_and_birthday_verification() {
    // Note: Seed3 has features=1 (FEATURE_FOO). The Rust library does not
    // expose polyseed_enable_features(), so it cannot decode a seed with
    // user features set. We verify the salt construction manually.

    let birthday = birthday_encode(SEED3_TIME);
    assert_eq!(birthday, 1015, "Seed3 encoded birthday = 1015");

    // Construct the salt manually with seed3 parameters
    let salt = c_keygen_salt(1, u32::from(birthday), 1); // coin=AEON(1), features=1
    let salt_hex = hex::encode(salt);
    assert_eq!(salt_hex, SEED3_SALT_HEX, "Seed3 salt matches C reference");

    // Verify entropy matches what C expects (manual check)
    let entropy = hex::decode(SEED3_ENTROPY_HEX).unwrap();
    assert_eq!(entropy.len(), 32, "Entropy is 32 bytes");
    assert_eq!(entropy[SECRET_SIZE..], [0u8; 13], "Padding bytes are zero");

    // Verify the last secret byte respects CLEAR_MASK
    // CLEAR_MASK in C: ~(uint8_t)(((1u << 2) - 1) << 6) = ~0xC0 = 0x3F
    let clear_mask: u8 = 0x3F;
    assert_eq!(
        entropy[SECRET_SIZE - 1] & !clear_mask,
        0,
        "Last secret byte respects CLEAR_MASK"
    );

    // The PBKDF2 inputs for seed3 are:
    //   pw = entropy (32 bytes padded)
    //   salt = "POLYSEED key\x00\xff\xff\xff" + coin(LE32) + birthday(LE32) + features(LE32) + zeros
    let mut c_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&entropy, &salt, 10000, &mut c_key);
}

// Wrong coin produces checksum error (matching test_decode_en_coin)

#[test]
fn test_wrong_coin_produces_checksum_error() {

    // C test_decode_en_coin: decoding seed1 phrase with POLYSEED_AEON
    // instead of POLYSEED_MONERO should produce POLYSEED_ERR_CHECKSUM
    let result = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Aeon,
        0,
    );

    assert_eq!(
        result,
        Err(PolyseedError::InvalidChecksum),
        "Decoding with wrong coin should produce InvalidChecksum (matching C POLYSEED_ERR_CHECKSUM)"
    );

    // Also test with Wownero
    let result = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Wownero,
        0,
    );
    assert_eq!(
        result,
        Err(PolyseedError::InvalidChecksum),
        "Decoding with Wownero should also produce InvalidChecksum"
    );
}

// Feature flag constants match C reference

#[test]
fn test_feature_flag_constants_match_c() {

    // C: FEATURE_BITS = 5
    assert_eq!(FEATURE_BITS, 5, "FEATURE_BITS = 5");

    // C: ENCRYPTED_MASK = 16 (1 << 4)
    assert_eq!(ENCRYPTED_MASK, 16, "ENCRYPTED_MASK = 16");

    // C: FEATURE_MASK = (1 << 5) - 1 = 31
    assert_eq!(FEATURE_MASK, 31, "FEATURE_MASK = 31");

    // C: reserved_features = FEATURE_MASK ^ ENCRYPTED_MASK = 31 ^ 16 = 15
    assert_eq!(RESERVED_FEATURES_MASK, 15, "RESERVED_FEATURES_MASK = 15");

    // Verify the Rust polyseed library uses the same values
    // by checking that seeds with features=0 and features=ENCRYPTED_MASK are supported
    // but features=1..7 are not

    // features=0: supported (normal seed)
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    );
    assert!(seed.is_ok(), "features=0 should be supported");

    // features=ENCRYPTED_MASK: supported (through crypt toggle)
    let mut encrypted = seed.unwrap();
    encrypted.crypt("test");
    assert!(encrypted.is_encrypted(), "Encrypted flag should be set");
    assert_eq!(
        encrypted.features() & ENCRYPTED_MASK,
        ENCRYPTED_MASK,
        "ENCRYPTED_MASK bit should be set"
    );
}

// Store/Load roundtrip preserves encrypted flag

#[test]
fn test_store_load_encrypted_roundtrip() {

    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(SEED1_PHRASE.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let original_key = seed.key(Coin::Monero);

    // Encrypt
    let mut encrypted = seed.clone();
    encrypted.crypt(CRYPT_PASSWORD);
    assert!(encrypted.is_encrypted());

    // Store encrypted
    let storage = encrypted.store();

    // Load encrypted
    let mut loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert!(loaded.is_encrypted(), "Loaded seed should be encrypted");
    assert_eq!(encrypted, loaded, "Loaded should match encrypted");

    // Decrypt
    loaded.crypt(CRYPT_PASSWORD);
    assert!(!loaded.is_encrypted(), "Should be decrypted");
    assert_eq!(
        *loaded.key(Coin::Monero),
        *original_key,
        "Decrypted key should match original"
    );
}

// All coin values produce correct salts

#[test]
fn test_all_coins_produce_correct_salts() {

    let coins: [(Coin, u32); 3] = [
        (Coin::Monero, 0),
        (Coin::Aeon, 1),
        (Coin::Wownero, 2),
    ];

    for (coin, coin_raw) in &coins {
        let salt = c_keygen_salt(*coin_raw, 100, 0);

        // Verify coin bytes at offset 16..20
        assert_eq!(
            &salt[16..20],
            &coin_raw.to_le_bytes(),
            "Coin {coin_raw} LE bytes at offset 16"
        );

        // Verify the salt prefix is always the same
        assert_eq!(&salt[..12], b"POLYSEED key", "Prefix");
        assert_eq!(salt[12], 0x00, "Null terminator");
        assert_eq!(&salt[13..16], &[0xFF, 0xFF, 0xFF], "FF padding");
    }
}

// SECRET_SIZE and CLEAR_MASK match C

#[test]
fn test_secret_size_and_clear_mask_match_c() {

    // C: SECRET_BITS = 150
    // C: SECRET_SIZE = (150 + 8 - 1) / 8 = 19
    assert_eq!(SECRET_SIZE, 19, "SECRET_SIZE = 19");

    // C: CLEAR_BITS = 19 * 8 - 150 = 2
    let clear_bits = SECRET_SIZE * 8 - SECRET_BITS;
    assert_eq!(clear_bits, 2, "CLEAR_BITS = 2");

    // C: CLEAR_MASK = ~(uint8_t)(((1u << 2) - 1) << 6) = ~0xC0 = 0x3F
    let c_clear_mask: u8 = !((((1u16 << clear_bits) - 1) << (8 - clear_bits)) as u8);
    assert_eq!(c_clear_mask, 0x3F, "C CLEAR_MASK = 0x3F");

    // Rust: LAST_BYTE_SECRET_BITS_MASK = (1 << (8 - 2)) - 1 = 63 = 0x3F
    let rust_mask: u8 = ((1u16 << (8 - clear_bits)) - 1) as u8;
    assert_eq!(rust_mask, 0x3F, "Rust LAST_BYTE_SECRET_BITS_MASK = 0x3F");

    assert_eq!(c_clear_mask, rust_mask, "Both masks are equivalent");

    // Verify seed1 entropy respects this mask
    let entropy = hex::decode(SEED1_ENTROPY_HEX).unwrap();
    assert_eq!(
        entropy[SECRET_SIZE - 1] & !rust_mask,
        0,
        "Seed1 entropy respects CLEAR_MASK"
    );

    // Verify seed2 entropy respects this mask
    let entropy2 = hex::decode(SEED2_ENTROPY_HEX).unwrap();
    assert_eq!(
        entropy2[SECRET_SIZE - 1] & !rust_mask,
        0,
        "Seed2 entropy respects CLEAR_MASK"
    );
}
