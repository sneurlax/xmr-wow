use zeroize::Zeroizing;
use rand_core::OsRng;

use crate::*;

#[test]
fn test_polyseed() {
  struct Vector {
    language: Language,
    seed: String,
    entropy: String,
    birthday: u64,
    has_prefix: bool,
    has_accent: bool,
  }

  let vectors = [
    Vector {
      language: Language::English,
      seed: "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language"
        .into(),
      entropy: "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000".into(),
      birthday: 1638446400,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Spanish,
      seed: "eje fin parte célebre tabú pestaña lienzo puma \
      prisión hora regalo lengua existir lápiz lote sonoro"
        .into(),
      entropy: "5a2b02df7db21fcbe6ec6df137d54c7b20fd2b00000000000000000000000000".into(),
      birthday: 3118651200,
      has_prefix: true,
      has_accent: true,
    },
    Vector {
      language: Language::French,
      seed: "valable arracher décaler jeudi amusant dresser mener épaissir risible \
      prouesse réserve ampleur ajuster muter caméra enchère"
        .into(),
      entropy: "11cfd870324b26657342c37360c424a14a050b00000000000000000000000000".into(),
      birthday: 1679314966,
      has_prefix: true,
      has_accent: true,
    },
    Vector {
      language: Language::Italian,
      seed: "caduco midollo copione meninge isotopo illogico riflesso tartaruga fermento \
      olandese normale tristezza episodio voragine forbito achille"
        .into(),
      entropy: "7ecc57c9b4652d4e31428f62bec91cfd55500600000000000000000000000000".into(),
      birthday: 1679316358,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Portuguese,
      seed: "caverna custear azedo adeus senador apertada sedoso omitir \
      sujeito aurora videira molho cartaz gesso dentista tapar"
        .into(),
      entropy: "45473063711376cae38f1b3eba18c874124e1d00000000000000000000000000".into(),
      birthday: 1679316657,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Czech,
      seed: "usmrtit nora dotaz komunita zavalit funkce mzda sotva akce \
      vesta kabel herna stodola uvolnit ustrnout email"
        .into(),
      entropy: "7ac8a4efd62d9c3c4c02e350d32326df37821c00000000000000000000000000".into(),
      birthday: 1679316898,
      has_prefix: true,
      has_accent: false,
    },
    Vector {
      language: Language::Korean,
      seed: "전망 선풍기 국제 무궁화 설사 기름 이론적 해안 절망 예선 \
        지우개 보관 절망 말기 시각 귀신"
        .into(),
      entropy: "684663fda420298f42ed94b2c512ed38ddf12b00000000000000000000000000".into(),
      birthday: 1679317073,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: Language::Japanese,
      seed: "うちあわせ　ちつじょ　つごう　しはい　けんこう　とおる　てみやげ　はんとし　たんとう \
      といれ　おさない　おさえる　むかう　ぬぐう　なふだ　せまる"
        .into(),
      entropy: "94e6665518a6286c6e3ba508a2279eb62b771f00000000000000000000000000".into(),
      birthday: 1679318722,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: Language::ChineseTraditional,
      seed: "亂 挖 斤 柄 代 圈 枝 轄 魯 論 函 開 勘 番 榮 壁".into(),
      entropy: "b1594f585987ab0fd5a31da1f0d377dae5283f00000000000000000000000000".into(),
      birthday: 1679426433,
      has_prefix: false,
      has_accent: false,
    },
    Vector {
      language: Language::ChineseSimplified,
      seed: "啊 百 族 府 票 划 伪 仓 叶 虾 借 溜 晨 左 等 鬼".into(),
      entropy: "21cdd366f337b89b8d1bc1df9fe73047c22b0300000000000000000000000000".into(),
      birthday: 1679426817,
      has_prefix: false,
      has_accent: false,
    },
    // The following seed requires the language specification in order to calculate
    // a single valid checksum
    Vector {
      language: Language::Spanish,
      seed: "impo sort usua cabi venu nobl oliv clim \
        cont barr marc auto prod vaca torn fati"
        .into(),
      entropy: "dbfce25fe09b68a340e01c62417eeef43ad51800000000000000000000000000".into(),
      birthday: 1701511650,
      has_prefix: true,
      has_accent: true,
    },
  ];

  for vector in vectors {
    let add_whitespace = |mut seed: String| {
      seed.push(' ');
      seed
    };

    let seed_without_accents = |seed: &str| {
      seed
        .split_whitespace()
        .map(|w| w.nfkd().filter(|c| c.is_ascii()).collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
    };

    let trim_seed = |seed: &str| {
      let seed_to_trim =
        if vector.has_accent { seed_without_accents(seed) } else { seed.to_string() };
      seed_to_trim
        .split_whitespace()
        .map(|w| {
          let mut ascii = 0;
          let mut to_take = w.len();
          for (i, char) in w.chars().enumerate() {
            if char.is_ascii() {
              ascii += 1;
            }
            if ascii == PREFIX_LEN {
              // +1 to include this character, which put us at the prefix length
              to_take = i + 1;
              break;
            }
          }
          w.chars().take(to_take).collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
    };

    // String -> Seed
    println!("{}. language: {:?}, seed: {}", line!(), vector.language, vector.seed.clone());
    let seed = Polyseed::from_string(vector.language, Zeroizing::new(vector.seed.clone()), Coin::Monero, 0).unwrap();
    let trim = trim_seed(&vector.seed);
    let add_whitespace = add_whitespace(vector.seed.clone());
    let seed_without_accents = seed_without_accents(&vector.seed);

    // Make sure a version with added whitespace still works
    let whitespaced_seed =
      Polyseed::from_string(vector.language, Zeroizing::new(add_whitespace), Coin::Monero, 0).unwrap();
    assert_eq!(seed, whitespaced_seed);
    // Check trimmed versions works
    if vector.has_prefix {
      let trimmed_seed = Polyseed::from_string(vector.language, Zeroizing::new(trim), Coin::Monero, 0).unwrap();
      assert_eq!(seed, trimmed_seed);
    }
    // Check versions without accents work
    if vector.has_accent {
      let seed_without_accents =
        Polyseed::from_string(vector.language, Zeroizing::new(seed_without_accents), Coin::Monero, 0).unwrap();
      assert_eq!(seed, seed_without_accents);
    }

    let entropy = Zeroizing::new(hex::decode(vector.entropy).unwrap().try_into().unwrap());
    assert_eq!(*seed.entropy(), entropy);
    assert!(seed.birthday().abs_diff(vector.birthday) < TIME_STEP);

    // Entropy -> Seed
    let from_entropy = Polyseed::from(vector.language, 0, seed.birthday(), entropy).unwrap();
    assert_eq!(seed.to_string(Coin::Monero), from_entropy.to_string(Coin::Monero));

    // Check against ourselves
    {
      let seed = Polyseed::new(&mut OsRng, vector.language);
      println!("{}. seed: {}", line!(), *seed.to_string(Coin::Monero));
      assert_eq!(seed, Polyseed::from_string(vector.language, seed.to_string(Coin::Monero), Coin::Monero, 0).unwrap());
      assert_eq!(
        seed,
        Polyseed::from(vector.language, 0, seed.birthday(), seed.entropy().clone(),).unwrap()
      );
    }
  }
}

#[test]
fn test_invalid_polyseed() {
  // This seed includes unsupported features bits and should error on decode
  let seed = "include domain claim resemble urban hire lunch bird \
    crucial fire best wife ring warm ignore model"
    .into();
  let res = Polyseed::from_string(Language::English, Zeroizing::new(seed), Coin::Monero, 0);
  assert_eq!(res, Err(PolyseedError::UnsupportedFeatures));
}

#[test]
fn test_key() {
  let seed: String = "comic blanket chair inject end snow rural improve cereal \
     better initial replace ribbon brother gather unaware"
    .into();
  let res = Polyseed::from_string(Language::English, Zeroizing::new(seed), Coin::Monero, 0).unwrap();
  let key = res.key(Coin::Monero);
  assert_eq!(
    *key,
    [
      216, 82, 37, 164, 252, 122, 170, 61, 52, 152, 131, 26, 181, 226, 191, 131, 204, 3, 242, 225,
      229, 175, 37, 151, 18, 143, 53, 175, 136, 17, 47, 126
    ]
  );
}

#[test]
fn test_is_encrypted() {
  let seed = Polyseed::new(&mut OsRng, Language::English);
  assert!(!seed.is_encrypted(), "A newly created seed should not be encrypted");
}

#[test]
fn test_crypt_roundtrip() {
  let seed_str = "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  let original = Polyseed::from_string(Language::English, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  let original_entropy = original.entropy().clone();

  // Encrypt
  let mut encrypted = original.clone();
  encrypted.crypt("password");
  assert!(encrypted.is_encrypted(), "Seed should be encrypted after crypt");
  assert_ne!(encrypted.entropy(), &original_entropy, "Encrypted entropy should differ");

  // Decrypt
  encrypted.crypt("password");
  assert!(!encrypted.is_encrypted(), "Seed should be decrypted after second crypt");
  assert_eq!(encrypted.entropy(), &original_entropy, "Decrypted entropy should match original");
  assert_eq!(encrypted, original, "Decrypted seed should match original");
}

#[test]
fn test_crypt_salt_and_mask_vector() {
  use sha2::Sha256;
  use pbkdf2::pbkdf2_hmac;

  let password = "password";
  let mut salt = [0u8; 16];
  salt[.. 13].copy_from_slice(b"POLYSEED mask");
  salt[14] = 0xFF;
  salt[15] = 0xFF;

  assert_eq!(hex::encode(&salt), "504f4c5953454544206d61736b00ffff");

  let mut mask = [0u8; 32];
  pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 10000, &mut mask);

  assert_eq!(
    hex::encode(&mask),
    "886777de23641e21a0fd252d37a9d06b2d87fd1f3c8c001624e909b31f2c9be5"
  );
}

#[test]
fn test_store_load_roundtrip() {
  let seed_str = "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  let seed = Polyseed::from_string(Language::English, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();

  let storage = seed.store();
  assert_eq!(&storage[.. 8], b"POLYSEED");
  assert_eq!(storage[29], 0xFF);

  let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
  assert_eq!(seed, loaded);
  assert_eq!(*seed.entropy(), *loaded.entropy());
  assert_eq!(seed.birthday(), loaded.birthday());
  assert_eq!(seed.features(), loaded.features());

  let random_seed = Polyseed::new(&mut OsRng, Language::Japanese);
  let storage2 = random_seed.store();
  let loaded2 = Polyseed::load(&storage2, Language::Japanese, 0).unwrap();
  assert_eq!(random_seed, loaded2);
}

#[test]
fn test_load_invalid_format() {
  let mut storage = [0u8; 32];
  storage[.. 8].copy_from_slice(b"BADHEADR");
  assert_eq!(Polyseed::load(&storage, Language::English, 0), Err(PolyseedError::InvalidFormat));

  let seed = Polyseed::new(&mut OsRng, Language::English);
  let mut storage = *seed.store();
  storage[29] = 0x00;
  assert_eq!(Polyseed::load(&storage, Language::English, 0), Err(PolyseedError::InvalidFormat));

  let mut storage = *seed.store();
  storage[30] = 0x00;
  storage[31] = 0x00;
  assert_eq!(Polyseed::load(&storage, Language::English, 0), Err(PolyseedError::InvalidFormat));
}

#[test]
fn test_crypt_store_load_roundtrip() {
  let seed_str = "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  let original = Polyseed::from_string(Language::English, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();

  let mut encrypted = original.clone();
  encrypted.crypt("my_password");
  assert!(encrypted.is_encrypted());

  let storage = encrypted.store();
  let mut loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
  assert!(loaded.is_encrypted());
  assert_eq!(encrypted, loaded);

  loaded.crypt("my_password");
  assert!(!loaded.is_encrypted());
  assert_eq!(original, loaded);
}

#[test]
fn test_from_string_auto_english() {
  let seed_str = "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  let (seed, lang) = Polyseed::from_string_auto(Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  assert_eq!(lang, Language::English);
  let expected = Polyseed::from_string(Language::English, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  assert_eq!(seed, expected);
}

#[test]
fn test_from_string_auto_japanese() {
  let seed_str = "うちあわせ　ちつじょ　つごう　しはい　けんこう　とおる　てみやげ　はんとし　たんとう \
      といれ　おさない　おさえる　むかう　ぬぐう　なふだ　せまる";
  let (seed, lang) = Polyseed::from_string_auto(Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  assert_eq!(lang, Language::Japanese);
  let expected = Polyseed::from_string(Language::Japanese, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  assert_eq!(seed, expected);
}

#[test]
fn test_from_string_auto_invalid() {
  let garbage = Zeroizing::new("xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx xxx".into());
  let result = Polyseed::from_string_auto(garbage, Coin::Monero, 0);
  assert_eq!(result, Err(PolyseedError::InvalidSeed));
}

#[test]
fn test_from_string_auto_wrong_word_count() {
  let too_few = Zeroizing::new("raven tail swear".into());
  let result = Polyseed::from_string_auto(too_few, Coin::Monero, 0);
  // All languages fail with InvalidWordCount, which means no match -> InvalidSeed
  assert_eq!(result, Err(PolyseedError::InvalidSeed));
}

#[test]
fn test_enable_features() {
  const FEATURE_FOO: u8 = 1;
  const FEATURE_BAR: u8 = 2;
  const FEATURE_QUX: u8 = 4;

  // Without enabling features, creating a seed with user features should fail
  let mut entropy = Zeroizing::new([0u8; 32]);
  entropy[0] = 0x42;
  assert_eq!(
    Polyseed::from_internal(Language::English, FEATURE_FOO, 0, entropy.clone(), 0),
    Err(PolyseedError::UnsupportedFeatures)
  );

  // With features enabled, it should succeed
  let seed = Polyseed::from_internal(
    Language::English, FEATURE_FOO, 0, entropy.clone(), FEATURE_FOO | FEATURE_BAR | FEATURE_QUX,
  ).unwrap();
  assert_eq!(get_feature(seed.features(), FEATURE_FOO), FEATURE_FOO);
  assert_eq!(get_feature(seed.features(), FEATURE_BAR), 0);
  assert_eq!(get_feature(seed.features(), FEATURE_QUX), 0);

  // Create with BAR feature
  let seed_bar = Polyseed::from_internal(
    Language::English, FEATURE_BAR, 0, entropy.clone(), FEATURE_FOO | FEATURE_BAR,
  ).unwrap();
  assert_eq!(get_feature(seed_bar.features(), FEATURE_BAR), FEATURE_BAR);
  assert_eq!(get_feature(seed_bar.features(), FEATURE_FOO), 0);

  // Enable only FOO, then BAR should be rejected
  assert_eq!(
    Polyseed::from_internal(Language::English, FEATURE_BAR, 0, entropy.clone(), FEATURE_FOO),
    Err(PolyseedError::UnsupportedFeatures)
  );

  // Decode a seed with features using enabled_features parameter
  let seed_with_feat = Polyseed::from(Language::English, FEATURE_FOO, 1635768000, entropy.clone()).unwrap();
  let phrase = seed_with_feat.to_string(Coin::Monero);

  // Without enabling, decode should fail with UnsupportedFeatures
  let res = Polyseed::from_string(Language::English, phrase.clone(), Coin::Monero, 0);
  assert_eq!(res, Err(PolyseedError::UnsupportedFeatures));

  // With enabling, decode should succeed
  let decoded = Polyseed::from_string(Language::English, phrase, Coin::Monero, FEATURE_FOO).unwrap();
  assert_eq!(decoded, seed_with_feat);

  // Store/load with features
  let storage = seed_with_feat.store();
  let loaded = Polyseed::load(&storage, Language::English, FEATURE_FOO).unwrap();
  assert_eq!(loaded, seed_with_feat);

  // Load without enabling should fail
  let res = Polyseed::load(&storage, Language::English, 0);
  assert_eq!(res, Err(PolyseedError::UnsupportedFeatures));
}

#[test]
fn test_nfc_output_japanese() {
  // Japanese should use ideographic space separator
  let seed_str = "うちあわせ　ちつじょ　つごう　しはい　けんこう　とおる　てみやげ　はんとし　たんとう \
      といれ　おさない　おさえる　むかう　ぬぐう　なふだ　せまる";
  let seed = Polyseed::from_string(Language::Japanese, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  let output = seed.to_string(Coin::Monero);

  // Count ideographic spaces (U+3000)
  let ideographic_spaces = output.chars().filter(|&c| c == '\u{3000}').count();
  assert_eq!(ideographic_spaces, 15, "Japanese output should have 15 ideographic space separators");

  // Should not contain ASCII spaces
  let ascii_spaces = output.chars().filter(|&c| c == ' ').count();
  assert_eq!(ascii_spaces, 0, "Japanese output should not contain ASCII spaces");
}

#[test]
fn test_invalid_checksum_on_corrupted_word() {
  // Known-good seed
  let good = "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  // Sanity: the good seed parses
  Polyseed::from_string(Language::English, Zeroizing::new(good.into()), Coin::Monero, 0).unwrap();

  // Replace one word ("tail" → "ability") to corrupt the checksum
  let bad = "raven ability swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  let res = Polyseed::from_string(Language::English, Zeroizing::new(bad.into()), Coin::Monero, 0);
  assert_eq!(res, Err(PolyseedError::InvalidChecksum));
}

#[test]
fn test_birthday_edge_cases() {
  // Before epoch: saturating_sub clamps to 0
  assert_eq!(birthday_encode(0), 0);

  // Exactly at epoch
  assert_eq!(birthday_encode(POLYSEED_EPOCH), 0);

  // One time-step after epoch
  assert_eq!(birthday_encode(POLYSEED_EPOCH + TIME_STEP), 1);

  // Max representable birthday (DATE_MASK = 1023)
  let max_time = POLYSEED_EPOCH + u64::from(DATE_MASK) * TIME_STEP;
  assert_eq!(birthday_encode(max_time), DATE_MASK);

  // Beyond max wraps via the mask
  let beyond = POLYSEED_EPOCH + (u64::from(DATE_MASK) + 1) * TIME_STEP;
  assert_eq!(birthday_encode(beyond), 0); // wraps to 0

  // Decode round-trips for all edge values
  assert_eq!(birthday_decode(0), POLYSEED_EPOCH);
  assert_eq!(birthday_decode(1), POLYSEED_EPOCH + TIME_STEP);
  assert_eq!(birthday_decode(DATE_MASK), POLYSEED_EPOCH + u64::from(DATE_MASK) * TIME_STEP);
}

#[test]
fn test_encrypted_mnemonic_roundtrip() {
  let seed_str = "raven tail swear infant grief assist regular lamp \
      duck valid someone little harsh puppy airport language";
  let original = Polyseed::from_string(Language::English, Zeroizing::new(seed_str.into()), Coin::Monero, 0).unwrap();
  let original_entropy = original.entropy().clone();

  // Encrypt
  let mut encrypted = original.clone();
  encrypted.crypt("roundtrip_test");
  assert!(encrypted.is_encrypted());

  // Encode to mnemonic
  let phrase = encrypted.to_string(Coin::Monero);

  // Decode from mnemonic
  let decoded = Polyseed::from_string(Language::English, phrase, Coin::Monero, 0).unwrap();
  assert!(decoded.is_encrypted(), "Decoded seed should still be encrypted");
  assert_eq!(*decoded.entropy(), *encrypted.entropy(), "Encrypted entropy preserved through mnemonic");

  // Decrypt and verify original
  let mut decrypted = decoded;
  decrypted.crypt("roundtrip_test");
  assert!(!decrypted.is_encrypted());
  assert_eq!(decrypted.entropy(), &original_entropy);
}
