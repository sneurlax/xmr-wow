//! Serialization verification tests.

use polyseed::{Coin, Language, Polyseed, PolyseedError};
use rand_core::OsRng;
use zeroize::Zeroizing;

// Constants replicated from the C reference for verification
const POLYSEED_EPOCH: u64 = 1635768000;
const TIME_STEP: u64 = 2629746;
const DATE_BITS: u8 = 10;
const DATE_MASK: u16 = (1u16 << DATE_BITS) - 1;
const SECRET_SIZE: usize = 19;
const STORAGE_EXTRA_BYTE: u8 = 0xFF;
const STORAGE_FOOTER: u16 = 0x7000;
const GF_MASK: u16 = (1u16 << 11) - 1;
#[allow(dead_code)]
const FEATURE_MASK: u8 = (1u8 << 5) - 1;

fn birthday_encode(time: u64) -> u16 {
    u16::try_from((time.saturating_sub(POLYSEED_EPOCH) / TIME_STEP) & u64::from(DATE_MASK))
        .expect("value masked by 2**10 - 1 didn't fit into a u16")
}

fn birthday_decode(birthday: u16) -> u64 {
    POLYSEED_EPOCH + (u64::from(birthday) * TIME_STEP)
}

// Manually construct a 32-byte binary blob matching the C format.
fn manual_store(features: u8, birthday: u16, secret: &[u8; 19], checksum: u16) -> [u8; 32] {
    let mut storage = [0u8; 32];
    // Header
    storage[..8].copy_from_slice(b"POLYSEED");
    // Extra field: (features << 10) | birthday
    let v1 = (u16::from(features) << DATE_BITS) | birthday;
    storage[8..10].copy_from_slice(&v1.to_le_bytes());
    // Secret
    storage[10..29].copy_from_slice(secret);
    // Extra byte
    storage[29] = STORAGE_EXTRA_BYTE;
    // Footer | checksum
    let v2 = STORAGE_FOOTER | checksum;
    storage[30..32].copy_from_slice(&v2.to_le_bytes());
    storage
}

// Verify store() binary layout matches C reference exactly
#[test]
fn test_store_binary_layout() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let storage = seed.store();

    // Byte [0..8]: Header must be "POLYSEED"
    assert_eq!(&storage[..8], b"POLYSEED", "Header mismatch");

    // Byte [8..10]: (features << 10) | birthday as LE u16
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let parsed_birthday = v1 & DATE_MASK;
    let parsed_features = v1 >> DATE_BITS;
    assert_eq!(parsed_features, u16::from(seed.features()), "Features mismatch in stored v1");
    // Birthday should encode time ~1638446400 => encoded birthday = 1
    assert_eq!(parsed_birthday, 1, "Birthday encoded value should be 1 for SEED_TIME1");

    // Byte [10..29]: 19 bytes of entropy
    assert_eq!(&storage[10..29], &seed.entropy()[..SECRET_SIZE], "Secret mismatch");

    // Byte [29]: Extra byte = 0xFF
    assert_eq!(storage[29], 0xFF, "Extra byte must be 0xFF");

    // Byte [30..32]: (0x7000 | checksum) as LE u16
    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    let parsed_checksum = v2 & GF_MASK;
    let parsed_footer = v2 & !GF_MASK;
    assert_eq!(parsed_footer, STORAGE_FOOTER, "Footer must be 0x7000");
    // Checksum must be within GF(2^11) range
    assert!(parsed_checksum < (1 << 11), "Checksum out of GF range");

    // Verify unused bytes are clean (byte [29] is extra byte, not entropy)
    // All entropy beyond SECRET_SIZE should be zero in the struct
    for i in SECRET_SIZE..32 {
        assert_eq!(seed.entropy()[i], 0, "Entropy byte {i} should be zero");
    }
}

// Dart test vector - decode base64 and verify load()
#[test]
fn test_dart_serialization_vector() {
    // Base64 "UE9MWVNFRUQWAP7QTFMwyWZ55hIVJOa7aluTxzP/Y3c=" decodes to:
    let dart_storage: [u8; 32] = [
        0x50, 0x4f, 0x4c, 0x59, 0x53, 0x45, 0x45, 0x44, // "POLYSEED"
        0x16, 0x00, // v1: birthday=22, features=0
        0xfe, 0xd0, 0x4c, 0x53, 0x30, 0xc9, 0x66, 0x79, // secret[0..8]
        0xe6, 0x12, 0x15, 0x24, 0xe6, 0xbb, 0x6a, 0x5b, // secret[8..16]
        0x93, 0xc7, 0x33, // secret[16..19]
        0xff, // extra byte
        0x63, 0x77, // v2: footer=0x7000, checksum
    ];

    // Verify header
    assert_eq!(&dart_storage[..8], b"POLYSEED", "Dart vector header mismatch");

    // Verify extra byte
    assert_eq!(dart_storage[29], 0xFF, "Dart vector extra byte mismatch");

    // Verify footer
    let v2 = u16::from_le_bytes([dart_storage[30], dart_storage[31]]);
    let footer = v2 & !GF_MASK;
    assert_eq!(footer, STORAGE_FOOTER, "Dart vector footer mismatch");

    // Parse birthday
    let v1 = u16::from_le_bytes([dart_storage[8], dart_storage[9]]);
    let encoded_birthday = v1 & DATE_MASK;
    assert_eq!(encoded_birthday, 22, "Dart vector encoded birthday should be 22");
    let decoded_birthday = birthday_decode(encoded_birthday);
    assert_eq!(decoded_birthday, 1693622412, "Dart vector decoded birthday should be 1693622412");

    // Load in Rust -- this exercises the full load() path
    let loaded = Polyseed::load(&dart_storage, Language::English, 0).unwrap();

    // Verify birthday matches Dart expectation
    assert_eq!(loaded.birthday(), 1693622412, "Loaded birthday must match Dart expected value");

    // Verify features = 0
    assert_eq!(loaded.features(), 0, "Loaded features should be 0");

    // Verify not encrypted
    assert!(!loaded.is_encrypted(), "Loaded seed should not be encrypted");

    // Verify entropy matches what's in the binary
    let expected_secret: [u8; 19] = [
        0xfe, 0xd0, 0x4c, 0x53, 0x30, 0xc9, 0x66, 0x79,
        0xe6, 0x12, 0x15, 0x24, 0xe6, 0xbb, 0x6a, 0x5b,
        0x93, 0xc7, 0x33,
    ];
    assert_eq!(&loaded.entropy()[..19], &expected_secret, "Loaded entropy mismatch");

    // Verify store() round-trips back to the exact same bytes
    let re_stored = loaded.store();
    assert_eq!(*re_stored, dart_storage, "store(load(dart_bytes)) must reproduce exact bytes");
}

// Verify the Dart phrase produces the same stored bytes
#[test]
fn test_dart_phrase_to_store_matches_vector() {
    let phrase = "unaware yard donate shallow slot sing oil oxygen \
                  loyal bench near hill surround forum execute lamp";
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    let storage = seed.store();

    // The stored bytes should match the Dart base64 vector
    let dart_storage: [u8; 32] = [
        0x50, 0x4f, 0x4c, 0x59, 0x53, 0x45, 0x45, 0x44,
        0x16, 0x00,
        0xfe, 0xd0, 0x4c, 0x53, 0x30, 0xc9, 0x66, 0x79,
        0xe6, 0x12, 0x15, 0x24, 0xe6, 0xbb, 0x6a, 0x5b,
        0x93, 0xc7, 0x33,
        0xff,
        0x63, 0x77,
    ];

    assert_eq!(
        *storage, dart_storage,
        "Rust store() of the Dart phrase must produce the exact same bytes as the Dart implementation"
    );
}

// Store/Load round-trip for multiple seeds
#[test]
fn test_store_load_roundtrip_multiple_seeds() {
    // Test vector 1: English, features=0, birthday~1638446400
    {
        let phrase = "raven tail swear infant grief assist regular lamp \
                      duck valid someone little harsh puppy airport language";
        let seed = Polyseed::from_string(
            Language::English,
            Zeroizing::new(phrase.to_string()),
            Coin::Monero,
            0,
        )
        .unwrap();
        let storage = seed.store();
        let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
        assert_eq!(seed, loaded, "Round-trip failed for seed1");
        assert_eq!(seed.birthday(), loaded.birthday());
        assert_eq!(seed.features(), loaded.features());
        assert_eq!(*seed.entropy(), *loaded.entropy());
    }

    // Test vector 2: Spanish, features=0, birthday~3118651200
    {
        let phrase = "eje fin parte c\u{00e9}lebre tab\u{00fa} pesta\u{00f1}a lienzo puma \
                      prisi\u{00f3}n hora regalo lengua existir l\u{00e1}piz lote sonoro";
        let seed = Polyseed::from_string(
            Language::Spanish,
            Zeroizing::new(phrase.to_string()),
            Coin::Monero,
            0,
        )
        .unwrap();
        let storage = seed.store();
        let loaded = Polyseed::load(&storage, Language::Spanish, 0).unwrap();
        assert_eq!(seed, loaded, "Round-trip failed for seed2");
    }

    // Test vector 3: Random seeds in all languages
    for lang in [
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
    ] {
        let seed = Polyseed::new(&mut OsRng, lang);
        let storage = seed.store();
        let loaded = Polyseed::load(&storage, lang, 0).unwrap();
        assert_eq!(seed, loaded, "Round-trip failed for language {:?}", lang);
    }
}

// Encrypted seed store/load round-trip
#[test]
fn test_encrypted_store_load_roundtrip() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    let original = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();
    assert!(!original.is_encrypted());

    // Encrypt
    let mut encrypted = original.clone();
    encrypted.crypt("test_password");
    assert!(encrypted.is_encrypted(), "Seed must be encrypted after crypt()");

    // Store encrypted seed
    let storage = encrypted.store();

    // Verify header is still valid
    assert_eq!(&storage[..8], b"POLYSEED");

    // Parse features: should have encrypted bit set
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let stored_features = (v1 >> DATE_BITS) as u8;
    assert_ne!(stored_features & 0x10, 0, "Encrypted bit must be set in stored features");

    // Load encrypted seed
    let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
    assert!(loaded.is_encrypted(), "Loaded seed must be encrypted");
    assert_eq!(encrypted, loaded, "Encrypted round-trip must preserve all fields");

    // Decrypt loaded seed
    let mut decrypted = loaded;
    decrypted.crypt("test_password");
    assert!(!decrypted.is_encrypted(), "Decrypted seed must not be encrypted");
    assert_eq!(original, decrypted, "Decrypted seed must match original");
}

// Load validation - corrupt header
#[test]
fn test_load_corrupt_header() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    let mut storage = *seed.store();

    // Corrupt each header byte individually
    for i in 0..8 {
        let original = storage[i];
        storage[i] ^= 0x01;
        let result = Polyseed::load(&storage, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Corrupted header byte {i} should produce InvalidFormat"
        );
        storage[i] = original;
    }

    // Completely wrong header
    storage[..8].copy_from_slice(b"BADHEADR");
    assert_eq!(
        Polyseed::load(&storage, Language::English, 0),
        Err(PolyseedError::InvalidFormat),
        "Completely wrong header should produce InvalidFormat"
    );
}

// Load validation - corrupt extra byte (offset 29)
#[test]
fn test_load_corrupt_extra_byte() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    let mut storage = *seed.store();

    // Try every non-0xFF value
    for val in [0x00u8, 0x01, 0x7F, 0x80, 0xFE] {
        storage[29] = val;
        let result = Polyseed::load(&storage, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Extra byte 0x{val:02X} should produce InvalidFormat"
        );
    }
}

// Load validation - corrupt footer
#[test]
fn test_load_corrupt_footer() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    let storage = *seed.store();

    // Zero footer
    {
        let mut s = storage;
        s[30] = 0x00;
        s[31] = 0x00;
        let result = Polyseed::load(&s, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Zero footer should produce InvalidFormat"
        );
    }

    // Wrong footer bits (0x8000 instead of 0x7000)
    {
        let mut s = storage;
        let v2 = u16::from_le_bytes([s[30], s[31]]);
        let checksum = v2 & GF_MASK;
        let wrong_footer: u16 = 0x8000 | checksum;
        s[30..32].copy_from_slice(&wrong_footer.to_le_bytes());
        let result = Polyseed::load(&s, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Wrong footer (0x8000) should produce InvalidFormat"
        );
    }

    // Footer with extra bits set (0xF000 instead of 0x7000)
    {
        let mut s = storage;
        let v2 = u16::from_le_bytes([s[30], s[31]]);
        let checksum = v2 & GF_MASK;
        let bad_footer: u16 = 0xF000 | checksum;
        s[30..32].copy_from_slice(&bad_footer.to_le_bytes());
        let result = Polyseed::load(&s, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Footer with extra bits (0xF000) should produce InvalidFormat"
        );
    }
}

// Load validation - flip single bits (C test_format equivalent)
#[test]
fn test_load_flip_every_bit() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();
    let storage = *seed.store();

    // Verify the original loads successfully
    assert!(Polyseed::load(&storage, Language::English, 0).is_ok(), "Original should load");

    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mask = 1u8 << bit_idx;
            let mut corrupted = storage;
            corrupted[byte_idx] ^= mask;

            let result = Polyseed::load(&corrupted, Language::English, 0);
            assert!(
                result.is_err(),
                "Flipping bit {bit_idx} of byte {byte_idx} should cause load() to fail, \
                 but got Ok. original[{byte_idx}]=0x{:02X}, corrupted[{byte_idx}]=0x{:02X}",
                storage[byte_idx],
                corrupted[byte_idx]
            );

            // The error should be either InvalidFormat or InvalidChecksum
            match result {
                Err(PolyseedError::InvalidFormat) => {}
                Err(PolyseedError::InvalidChecksum) => {}
                Err(PolyseedError::UnsupportedFeatures) => {}
                Err(other) => panic!(
                    "Unexpected error for bit {bit_idx} of byte {byte_idx}: {:?}",
                    other
                ),
                Ok(_) => unreachable!(),
            }
        }
    }
}

// Verify features range check in v1 (values > FEATURE_MASK rejected)
#[test]
fn test_load_features_range_validation() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    let storage = *seed.store();

    // Inject features > FEATURE_MASK (> 31) into v1
    let v1_original = u16::from_le_bytes([storage[8], storage[9]]);
    let birthday = v1_original & DATE_MASK;

    // features = 32 (0x20) > FEATURE_MASK (0x1F) should fail
    {
        let mut s = storage;
        let bad_v1: u16 = (32u16 << DATE_BITS) | birthday;
        s[8..10].copy_from_slice(&bad_v1.to_le_bytes());
        let result = Polyseed::load(&s, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Features=32 should produce InvalidFormat"
        );
    }

    // features = 63 (0x3F) should also fail
    {
        let mut s = storage;
        let bad_v1: u16 = (63u16 << DATE_BITS) | birthday;
        s[8..10].copy_from_slice(&bad_v1.to_le_bytes());
        let result = Polyseed::load(&s, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Features=63 should produce InvalidFormat"
        );
    }
}

// Verify secret top bits validation (top 2 bits of secret[18] must be zero)
#[test]
fn test_load_secret_top_bits_validation() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    let mut storage = *seed.store();

    // Set bit 6 of secret[18] (storage offset 10+18=28)
    let original_28 = storage[28];
    storage[28] |= 0x40;
    if original_28 & 0x40 == 0 {
        // Only test if bit wasn't already set
        let result = Polyseed::load(&storage, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Secret with top bit 6 set should produce InvalidFormat"
        );
    }
    storage[28] = original_28;

    // Set bit 7 of secret[18]
    storage[28] |= 0x80;
    if original_28 & 0x80 == 0 {
        let result = Polyseed::load(&storage, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidFormat),
            "Secret with top bit 7 set should produce InvalidFormat"
        );
    }
}

// Verify manually constructed binary matches Rust store()
#[test]
fn test_manual_store_matches_rust_store() {
    let phrase = "raven tail swear infant grief assist regular lamp \
                  duck valid someone little harsh puppy airport language";
    let seed = Polyseed::from_string(
        Language::English,
        Zeroizing::new(phrase.to_string()),
        Coin::Monero,
        0,
    )
    .unwrap();

    // Extract fields from the seed
    let features = seed.features();
    let storage = seed.store();

    // Parse birthday and checksum from the stored bytes (since they're internal)
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let birthday_encoded = v1 & DATE_MASK;

    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    let checksum = v2 & GF_MASK;

    let mut secret = [0u8; 19];
    secret.copy_from_slice(&seed.entropy()[..19]);

    // Manually construct what C would produce
    let manual = manual_store(features, birthday_encoded, &secret, checksum);

    assert_eq!(
        *storage, manual,
        "Rust store() output must match manually constructed C-format binary"
    );
}

// C test vector 1 - create with known entropy and verify store
#[test]
fn test_c_seed1_store_format() {
    let entropy_bytes: [u8; 32] = {
        let mut e = [0u8; 32];
        e[..19].copy_from_slice(&[
            0xdd, 0x76, 0xe7, 0x35, 0x9a, 0x0d, 0xed, 0x37,
            0xcd, 0x0f, 0xf0, 0xf3, 0xc8, 0x29, 0xa5, 0xae,
            0x01, 0x67, 0x33,
        ]);
        e
    };

    let seed_time: u64 = 1638446400;
    let seed = Polyseed::from(
        Language::English,
        0,
        seed_time,
        Zeroizing::new(entropy_bytes),
    )
    .unwrap();

    let storage = seed.store();

    // Header
    assert_eq!(&storage[..8], b"POLYSEED");

    // v1: features=0, birthday=1
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    assert_eq!(v1 & DATE_MASK, 1, "Birthday should be 1");
    assert_eq!(v1 >> DATE_BITS, 0, "Features should be 0");

    // Secret
    assert_eq!(&storage[10..29], &entropy_bytes[..19]);

    // Extra byte
    assert_eq!(storage[29], 0xFF);

    // Footer
    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    assert_eq!(v2 & !GF_MASK, STORAGE_FOOTER);
}

// C test vector 2 - different birthday (birthday=563)
#[test]
fn test_c_seed2_store_format() {
    let entropy_bytes: [u8; 32] = {
        let mut e = [0u8; 32];
        e[..19].copy_from_slice(&[
            0x5a, 0x2b, 0x02, 0xdf, 0x7d, 0xb2, 0x1f, 0xcb,
            0xe6, 0xec, 0x6d, 0xf1, 0x37, 0xd5, 0x4c, 0x7b,
            0x20, 0xfd, 0x2b,
        ]);
        e
    };

    let seed_time: u64 = 3118651200;
    let expected_birthday = birthday_encode(seed_time);
    assert_eq!(expected_birthday, 563, "Encoded birthday should be 563");

    let seed = Polyseed::from(
        Language::Spanish,
        0,
        seed_time,
        Zeroizing::new(entropy_bytes),
    )
    .unwrap();

    let storage = seed.store();

    // v1: features=0, birthday=563
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    assert_eq!(v1 & DATE_MASK, 563, "Birthday should be 563");
    assert_eq!(v1 >> DATE_BITS, 0, "Features should be 0");

    // Verify round-trip
    let loaded = Polyseed::load(&storage, Language::Spanish, 0).unwrap();
    assert_eq!(seed, loaded);
}

// C test vector 3 - features=1 with AEON coin (birthday=1015).
// Rust rejects user features since polyseed_enable_features() is not exposed.
#[test]
fn test_c_seed3_with_features() {
    let seed_time: u64 = 4305268800;
    let expected_birthday = birthday_encode(seed_time);
    assert_eq!(expected_birthday, 1015, "Encoded birthday should be 1015");

    // Verify the v1 encoding for features=1, birthday=1015
    let v1: u16 = (1u16 << DATE_BITS) | 1015;
    assert_eq!(v1 & DATE_MASK, 1015);
    assert_eq!(v1 >> DATE_BITS, 1);

    // Verify the binary representation
    let v1_bytes = v1.to_le_bytes();
    // 1015 = 0x03F7, features=1 => v1 = (1 << 10) | 0x03F7 = 0x0400 | 0x03F7 = 0x07F7
    assert_eq!(v1, 0x07F7);
    assert_eq!(v1_bytes, [0xF7, 0x07]);

    // A seed with features=1 (user feature) should be rejected by load()
    // because Rust doesn't have polyseed_enable_features() -- this matches
    // C behavior when user features are not enabled.
    let entropy: [u8; 19] = [
        0x67, 0xb9, 0x36, 0xdf, 0xa4, 0xda, 0x6a, 0xe8,
        0xd3, 0xb3, 0xcd, 0xb3, 0xb9, 0x37, 0xf4, 0x02,
        0x7b, 0x0e, 0x3b,
    ];
    // We construct a valid-looking binary to test that load() rejects
    // unsupported features. We use a dummy checksum; the features check
    // comes before the checksum check in the Rust implementation.
    let mut storage = [0u8; 32];
    storage[..8].copy_from_slice(b"POLYSEED");
    storage[8..10].copy_from_slice(&v1_bytes);
    storage[10..29].copy_from_slice(&entropy);
    storage[29] = 0xFF;
    // Use a placeholder footer+checksum (the features check should trigger first)
    let v2: u16 = STORAGE_FOOTER | 0x000;
    storage[30..32].copy_from_slice(&v2.to_le_bytes());

    let result = Polyseed::load(&storage, Language::English, 0);
    assert_eq!(
        result,
        Err(PolyseedError::UnsupportedFeatures),
        "User features=1 should be rejected when not enabled"
    );
}

// Verify GF_MASK, FOOTER, and checksum bit packing
#[test]
fn test_footer_checksum_bit_packing() {
    // Verify no overlap between footer and checksum bits
    assert_eq!(STORAGE_FOOTER & GF_MASK, 0, "Footer and GF_MASK must not overlap");

    // Verify footer fits in the non-GF bits
    assert_eq!(STORAGE_FOOTER & !GF_MASK, STORAGE_FOOTER, "Footer must fit in upper bits");

    // Try various checksums
    for checksum in [0u16, 1, 0x3FF, 0x400, 0x7FF] {
        let v2 = STORAGE_FOOTER | checksum;
        assert_eq!(v2 & GF_MASK, checksum, "Checksum must be recoverable");
        assert_eq!(v2 & !GF_MASK, STORAGE_FOOTER, "Footer must be recoverable");
    }
}

// Multiple random seeds - stress test round-trip
#[test]
fn test_stress_roundtrip() {
    for _ in 0..50 {
        let seed = Polyseed::new(&mut OsRng, Language::English);
        let storage = seed.store();

        // Verify format invariants
        assert_eq!(&storage[..8], b"POLYSEED");
        assert_eq!(storage[29], 0xFF);
        let v2 = u16::from_le_bytes([storage[30], storage[31]]);
        assert_eq!(v2 & !GF_MASK, STORAGE_FOOTER);

        // Verify round-trip
        let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
        assert_eq!(seed, loaded);

        // Verify store is deterministic
        let storage2 = seed.store();
        assert_eq!(*storage, *storage2, "store() must be deterministic");
    }
}

// Verify that load() rejects all-zero storage
#[test]
fn test_load_all_zeros() {
    let storage = [0u8; 32];
    let result = Polyseed::load(&storage, Language::English, 0);
    assert_eq!(result, Err(PolyseedError::InvalidFormat));
}

// Verify that load() rejects all-0xFF storage
#[test]
fn test_load_all_ones() {
    let storage = [0xFFu8; 32];
    let result = Polyseed::load(&storage, Language::English, 0);
    assert_eq!(result, Err(PolyseedError::InvalidFormat));
}

// Checksum corruption specifically in the checksum field
#[test]
fn test_load_corrupt_checksum_only() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    let storage = *seed.store();

    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    let original_checksum = v2 & GF_MASK;

    // Try flipping just the checksum (keeping footer intact)
    for delta in [1u16, 2, 4, 8, 16, 0x100, 0x400] {
        let bad_checksum = (original_checksum ^ delta) & GF_MASK;
        if bad_checksum == original_checksum {
            continue;
        }
        let bad_v2 = STORAGE_FOOTER | bad_checksum;
        let mut s = storage;
        s[30..32].copy_from_slice(&bad_v2.to_le_bytes());
        let result = Polyseed::load(&s, Language::English, 0);
        assert_eq!(
            result,
            Err(PolyseedError::InvalidChecksum),
            "Corrupted checksum (delta={delta:#06x}) should produce InvalidChecksum"
        );
    }
}

// Verify encrypted seed has correct features in binary
#[test]
fn test_encrypted_features_in_binary() {
    let seed = Polyseed::new(&mut OsRng, Language::English);
    assert_eq!(seed.features(), 0);

    let mut encrypted = seed.clone();
    encrypted.crypt("password123");
    assert!(encrypted.is_encrypted());
    assert_eq!(encrypted.features() & 0x10, 0x10, "Encrypted flag must be set");

    let storage = encrypted.store();

    // Parse features from binary
    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let stored_features = (v1 >> DATE_BITS) as u8;
    assert_eq!(
        stored_features, encrypted.features(),
        "Stored features must match seed features"
    );
    assert_ne!(stored_features & 0x10, 0, "Encrypted bit must be set in binary");
}

// Verify v1 encoding/decoding symmetry
#[test]
fn test_v1_encoding_symmetry() {
    // Test all valid feature values (0..31) with various birthdays
    for features in 0u8..=31 {
        for birthday in [0u16, 1, 22, 100, 500, 563, 1015, 1023] {
            let v1 = (u16::from(features) << DATE_BITS) | birthday;
            let decoded_birthday = v1 & DATE_MASK;
            let decoded_features = v1 >> DATE_BITS;
            assert_eq!(decoded_birthday, birthday, "Birthday decode failed for f={features}, b={birthday}");
            assert_eq!(decoded_features, u16::from(features), "Features decode failed for f={features}, b={birthday}");
        }
    }
}
