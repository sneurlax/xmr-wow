#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;
use std_shims::{sync::LazyLock, vec::Vec, string::String, collections::HashMap};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing, ZeroizeOnDrop};
use rand_core::{RngCore, CryptoRng};

use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use unicode_normalization::UnicodeNormalization;

#[cfg(test)]
mod tests;

// Features
const FEATURE_BITS: u8 = 5;
#[allow(dead_code)]
const INTERNAL_FEATURES: u8 = 2;
const USER_FEATURES: u8 = 3;

const USER_FEATURES_MASK: u8 = (1 << USER_FEATURES) - 1;
const ENCRYPTED_MASK: u8 = 1 << 4;

fn user_features(features: u8) -> u8 {
  features & USER_FEATURES_MASK
}

/// Compute the reserved features mask given a set of enabled user feature bits.
fn reserved_features_mask(enabled: u8) -> u8 {
  let base: u8 = ((1 << FEATURE_BITS) - 1) ^ ENCRYPTED_MASK;
  base & !(enabled & USER_FEATURES_MASK)
}

fn polyseed_features_supported(features: u8, enabled: u8) -> bool {
  (features & reserved_features_mask(enabled)) == 0
}

/// Get the value of specific user feature bits from a seed's features.
pub fn get_feature(features: u8, mask: u8) -> u8 {
  features & (mask & USER_FEATURES_MASK)
}

// Dates
const DATE_BITS: u8 = 10;
const DATE_MASK: u16 = (1u16 << DATE_BITS) - 1;
const POLYSEED_EPOCH: u64 = 1635768000; // 1st November 2021 12:00 UTC
const TIME_STEP: u64 = 2629746; // 30.436875 days = 1/12 of the Gregorian year

// After ~85 years, this will roll over.
fn birthday_encode(time: u64) -> u16 {
  u16::try_from((time.saturating_sub(POLYSEED_EPOCH) / TIME_STEP) & u64::from(DATE_MASK))
    .expect("value masked by 2**10 - 1 didn't fit into a u16")
}

fn birthday_decode(birthday: u16) -> u64 {
  POLYSEED_EPOCH + (u64::from(birthday) * TIME_STEP)
}

// Polyseed parameters
const SECRET_BITS: usize = 150;

const BITS_PER_BYTE: usize = 8;
const SECRET_SIZE: usize = SECRET_BITS.div_ceil(BITS_PER_BYTE); // 19
const CLEAR_BITS: usize = (SECRET_SIZE * BITS_PER_BYTE) - SECRET_BITS; // 2

// Polyseed calls this CLEAR_MASK and has a very complicated formula for this fundamental
// equivalency
#[allow(clippy::cast_possible_truncation)]
const LAST_BYTE_SECRET_BITS_MASK: u8 = ((1 << (BITS_PER_BYTE - CLEAR_BITS)) - 1) as u8;

const SECRET_BITS_PER_WORD: usize = 10;

// The amount of words in a seed.
const POLYSEED_LENGTH: usize = 16;
// Amount of characters each word must have if trimmed
pub(crate) const PREFIX_LEN: usize = 4;

const POLY_NUM_CHECK_DIGITS: usize = 1;
const DATA_WORDS: usize = POLYSEED_LENGTH - POLY_NUM_CHECK_DIGITS;

// Polynomial
const GF_BITS: usize = 11;
const POLYSEED_MUL2_TABLE: [u16; 8] = [5, 7, 1, 3, 13, 15, 9, 11];

fn elem_mul2(x: u16) -> u16 {
  if x < 1024 {
    return 2 * x;
  }
  POLYSEED_MUL2_TABLE[usize::from(x % 8)] + (16 * ((x - 1024) / 8))
}

fn poly_eval(poly: &[u16; POLYSEED_LENGTH]) -> u16 {
  // Horner's method at x = 2
  let mut result = poly[POLYSEED_LENGTH - 1];
  for i in (0 .. (POLYSEED_LENGTH - 1)).rev() {
    result = elem_mul2(result) ^ poly[i];
  }
  result
}

// Key gen parameters
const POLYSEED_SALT: &[u8] = b"POLYSEED key";
const POLYSEED_KEYGEN_ITERATIONS: u32 = 10000;
const POLYSEED_CRYPT_ITERATIONS: u32 = 10000;

// Binary storage parameters
const STORAGE_HEADER: &[u8; 8] = b"POLYSEED";
const STORAGE_EXTRA_BYTE: u8 = 0xFF;
const STORAGE_FOOTER: u16 = 0x7000;
const GF_MASK: u16 = (1u16 << GF_BITS) - 1;
const FEATURE_MASK: u8 = (1u8 << FEATURE_BITS) - 1;

/// Coin types supported by Polyseed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub enum Coin {
  /// Monero.
  Monero,
  /// Aeon.
  Aeon,
  /// Wownero.
  Wownero,
}

impl Coin {
  fn to_raw(self) -> u16 {
    match self {
      Coin::Monero => 0,
      Coin::Aeon => 1,
      Coin::Wownero => 2,
    }
  }
}

/// An error when working with a Polyseed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum PolyseedError {
  /// The seed was invalid.
  #[cfg_attr(feature = "std", error("invalid seed"))]
  InvalidSeed,
  /// The entropy was invalid.
  #[cfg_attr(feature = "std", error("invalid entropy"))]
  InvalidEntropy,
  /// The checksum did not match the data.
  #[cfg_attr(feature = "std", error("invalid checksum"))]
  InvalidChecksum,
  /// Unsupported feature bits were set.
  #[cfg_attr(feature = "std", error("unsupported features"))]
  UnsupportedFeatures,
  /// The seed had an invalid word count.
  #[cfg_attr(feature = "std", error("invalid word count"))]
  InvalidWordCount,
  /// The binary storage format is invalid.
  #[cfg_attr(feature = "std", error("invalid format"))]
  InvalidFormat,
  /// Multiple languages matched during auto-detection.
  #[cfg_attr(feature = "std", error("multiple languages match"))]
  MultipleLanguagesMatch,
}

/// Language options for Polyseed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub enum Language {
  /// English.
  English,
  /// Spanish.
  Spanish,
  /// French.
  French,
  /// Italian.
  Italian,
  /// Japanese.
  Japanese,
  /// Korean.
  Korean,
  /// Czech.
  Czech,
  /// Portuguese.
  Portuguese,
  /// Simplified Chinese.
  ChineseSimplified,
  /// Traditional Chinese.
  ChineseTraditional,
}

const ALL_LANGUAGES: [Language; 10] = [
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

struct WordList {
  words: &'static [&'static str],
  has_prefix: bool,
  has_accent: bool,
  separator: &'static str,
  compose: bool,
}

impl WordList {
  fn new(
    words: &'static [&'static str],
    has_prefix: bool,
    has_accent: bool,
    separator: &'static str,
    compose: bool,
  ) -> WordList {
    let res = WordList { words, has_prefix, has_accent, separator, compose };
    assert!(words.len() < usize::from(u16::MAX));
    res
  }
}

static LANGUAGES: LazyLock<HashMap<Language, WordList>> = LazyLock::new(|| {
  HashMap::from([
    (Language::Czech, WordList::new(include!("./words/cs.rs"), true, false, " ", false)),
    (Language::French, WordList::new(include!("./words/fr.rs"), true, true, " ", true)),
    (Language::Korean, WordList::new(include!("./words/ko.rs"), false, false, " ", true)),
    (Language::English, WordList::new(include!("./words/en.rs"), true, false, " ", false)),
    (Language::Italian, WordList::new(include!("./words/it.rs"), true, false, " ", false)),
    (Language::Spanish, WordList::new(include!("./words/es.rs"), true, true, " ", true)),
    (Language::Japanese, WordList::new(include!("./words/ja.rs"), false, false, "\u{3000}", true)),
    (Language::Portuguese, WordList::new(include!("./words/pt.rs"), true, false, " ", false)),
    (
      Language::ChineseSimplified,
      WordList::new(include!("./words/zh_simplified.rs"), false, false, " ", false),
    ),
    (
      Language::ChineseTraditional,
      WordList::new(include!("./words/zh_traditional.rs"), false, false, " ", false),
    ),
  ])
});

/// A Polyseed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Polyseed {
  language: Language,
  features: u8,
  birthday: u16,
  entropy: Zeroizing<[u8; 32]>,
  checksum: u16,
}

impl fmt::Debug for Polyseed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("Polyseed").finish_non_exhaustive()
  }
}

fn valid_entropy(entropy: &Zeroizing<[u8; 32]>) -> bool {
  // Last byte of the entropy should only use certain bits
  let mut res =
    entropy[SECRET_SIZE - 1].ct_eq(&(entropy[SECRET_SIZE - 1] & LAST_BYTE_SECRET_BITS_MASK));
  // Last 13 bytes of the buffer should be unused
  for b in SECRET_SIZE .. entropy.len() {
    res &= entropy[b].ct_eq(&0);
  }
  res.into()
}

impl Polyseed {
  // TODO: Clean this
  fn to_poly(&self) -> Zeroizing<[u16; POLYSEED_LENGTH]> {
    let mut extra_bits = u32::from(FEATURE_BITS + DATE_BITS);
    let extra_val = (u16::from(self.features) << DATE_BITS) | self.birthday;

    let mut entropy_idx = 0;
    let mut secret_bits = BITS_PER_BYTE;
    let mut seed_rem_bits = SECRET_BITS - BITS_PER_BYTE;

    let mut poly = Zeroizing::new([0; POLYSEED_LENGTH]);
    for i in 0 .. DATA_WORDS {
      extra_bits -= 1;

      let mut word_bits = 0;
      let mut word_val = 0;
      while word_bits < SECRET_BITS_PER_WORD {
        if secret_bits == 0 {
          entropy_idx += 1;
          secret_bits = seed_rem_bits.min(BITS_PER_BYTE);
          seed_rem_bits -= secret_bits;
        }
        let chunk_bits = secret_bits.min(SECRET_BITS_PER_WORD - word_bits);
        secret_bits -= chunk_bits;
        word_bits += chunk_bits;
        word_val <<= chunk_bits;
        word_val |=
          (u16::from(self.entropy[entropy_idx]) >> secret_bits) & ((1u16 << chunk_bits) - 1);
      }

      word_val <<= 1;
      word_val |= (extra_val >> extra_bits) & 1;
      poly[POLY_NUM_CHECK_DIGITS + i] = word_val;
    }

    poly
  }

  fn from_internal(
    language: Language,
    masked_features: u8,
    encoded_birthday: u16,
    entropy: Zeroizing<[u8; 32]>,
    enabled_features: u8,
  ) -> Result<Polyseed, PolyseedError> {
    if !polyseed_features_supported(masked_features, enabled_features) {
      Err(PolyseedError::UnsupportedFeatures)?;
    }

    if !valid_entropy(&entropy) {
      Err(PolyseedError::InvalidEntropy)?;
    }

    let mut res = Polyseed {
      language,
      birthday: encoded_birthday,
      features: masked_features,
      entropy,
      checksum: 0,
    };
    res.checksum = poly_eval(&*res.to_poly());
    Ok(res)
  }

  /// Create a new `Polyseed` with specific internals.
  ///
  /// `birthday` is defined in seconds since the epoch.
  /// The `features` parameter specifies which user feature bits to set. Only the
  /// low 3 bits (values 1, 2, 4) are used; higher bits are masked off.
  pub fn from(
    language: Language,
    features: u8,
    birthday: u64,
    entropy: Zeroizing<[u8; 32]>,
  ) -> Result<Polyseed, PolyseedError> {
    let masked = user_features(features);
    Self::from_internal(language, masked, birthday_encode(birthday), entropy, masked)
  }

  /// Create a new `Polyseed`.
  ///
  /// This uses the system's time for the birthday, if available, else 0.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, language: Language) -> Polyseed {
    // Get the birthday
    #[cfg(feature = "std")]
    let birthday =
      SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(core::time::Duration::ZERO).as_secs();
    #[cfg(not(feature = "std"))]
    let birthday = 0;

    // Derive entropy
    let mut entropy = Zeroizing::new([0; 32]);
    rng.fill_bytes(entropy.as_mut());
    entropy[SECRET_SIZE ..].fill(0);
    entropy[SECRET_SIZE - 1] &= LAST_BYTE_SECRET_BITS_MASK;

    Self::from(language, 0, birthday, entropy).unwrap()
  }

  /// Create a new `Polyseed` from a String.
  #[allow(clippy::needless_pass_by_value)]
  pub fn from_string(
    lang: Language,
    seed: Zeroizing<String>,
    coin: Coin,
    enabled_features: u8,
  ) -> Result<Polyseed, PolyseedError> {
    let normalized: Zeroizing<String> = Zeroizing::new(seed.nfkd().collect());
    let words: Vec<&str> = normalized.split_whitespace().collect();
    if words.len() != POLYSEED_LENGTH {
      return Err(PolyseedError::InvalidWordCount);
    }

    let mut poly = Zeroizing::new([0u16; POLYSEED_LENGTH]);
    let lang_word_list: &WordList = &LANGUAGES[&lang];
    for (i, word) in words.into_iter().enumerate() {
      // Find the word's index
      fn check_if_matches<S: AsRef<str>, I: Iterator<Item = S>>(
        has_prefix: bool,
        mut lang_words: I,
        word: &str,
      ) -> Option<usize> {
        if has_prefix {
          // prefix match avoids false positives from substring overlap
          let mut get_position = || {
            lang_words.position(|lang_word| {
              let mut lang_word = lang_word.as_ref().chars();
              let mut word = word.chars();

              let mut res = true;
              for _ in 0 .. PREFIX_LEN {
                res &= lang_word.next() == word.next();
              }
              res
            })
          };
          let res = get_position();
          // If another word has this prefix, don't call it a match
          if get_position().is_some() {
            return None;
          }
          res
        } else {
          lang_words.position(|lang_word| lang_word.as_ref() == word)
        }
      }

      let Some(coeff) = (if lang_word_list.has_accent {
        let strip_accents =
          |word: &str| -> String { word.nfkd().filter(|c| c.is_ascii()).collect() };
        check_if_matches(
          lang_word_list.has_prefix,
          lang_word_list.words.iter().map(|lang_word| strip_accents(lang_word)),
          &strip_accents(word),
        )
      } else {
        check_if_matches(lang_word_list.has_prefix, lang_word_list.words.iter(), word)
      }) else {
        Err(PolyseedError::InvalidSeed)?
      };

      // WordList asserts the word list length is less than u16::MAX
      poly[i] = u16::try_from(coeff).expect("coeff exceeded u16");
    }

    // xor out the coin
    poly[POLY_NUM_CHECK_DIGITS] ^= coin.to_raw();

    // Validate the checksum
    if poly_eval(&poly) != 0 {
      Err(PolyseedError::InvalidChecksum)?;
    }

    // Convert the polynomial into entropy
    let mut entropy = Zeroizing::new([0; 32]);

    let mut extra = 0;

    let mut entropy_idx = 0;
    let mut entropy_bits = 0;

    let checksum = poly[0];
    for mut word_val in poly.iter().copied().skip(POLY_NUM_CHECK_DIGITS) {
      // Parse the bottom bit, which is one of the bits of extra
      // This iterates for less than 16 iters, meaning this won't drop any bits
      extra <<= 1;
      extra |= word_val & 1;
      word_val >>= 1;

      // 10 bits per word creates a [8, 2], [6, 4], [4, 6], [2, 8] cycle
      // 15 % 4 is 3, leaving 2 bits off, and 152 (19 * 8) - 2 is 150, the amount of bits in the
      // secret
      let mut word_bits = GF_BITS - 1;
      while word_bits > 0 {
        if entropy_bits == BITS_PER_BYTE {
          entropy_idx += 1;
          entropy_bits = 0;
        }
        let chunk_bits = word_bits.min(BITS_PER_BYTE - entropy_bits);
        word_bits -= chunk_bits;
        let chunk_mask = (1u16 << chunk_bits) - 1;
        if chunk_bits < BITS_PER_BYTE {
          entropy[entropy_idx] <<= chunk_bits;
        }
        entropy[entropy_idx] |=
          u8::try_from((word_val >> word_bits) & chunk_mask).expect("chunk exceeded u8");
        entropy_bits += chunk_bits;
      }
    }

    let birthday = extra & DATE_MASK;
    // extra is contained to u16, and DATE_BITS > 8
    let features =
      u8::try_from(extra >> DATE_BITS).expect("couldn't convert extra >> DATE_BITS to u8");

    let res = Self::from_internal(lang, features, birthday, entropy, enabled_features);
    if let Ok(res) = res.as_ref() {
      debug_assert_eq!(res.checksum, checksum);
    }
    res
  }

  /// Create a new `Polyseed` from a String, automatically detecting the language.
  #[allow(clippy::needless_pass_by_value)]
  pub fn from_string_auto(
    seed: Zeroizing<String>,
    coin: Coin,
    enabled_features: u8,
  ) -> Result<(Polyseed, Language), PolyseedError> {
    let mut result: Option<(Polyseed, Language)> = None;
    for lang in ALL_LANGUAGES {
      if let Ok(decoded) = Self::from_string(lang, seed.clone(), coin, enabled_features) {
        if result.is_some() {
          return Err(PolyseedError::MultipleLanguagesMatch);
        }
        result = Some((decoded, lang));
      }
    }
    result.ok_or(PolyseedError::InvalidSeed)
  }

  /// When this seed was created, defined in seconds since the epoch.
  pub fn birthday(&self) -> u64 {
    birthday_decode(self.birthday)
  }

  /// This seed's features.
  pub fn features(&self) -> u8 {
    self.features
  }

  /// Returns `true` if this seed is currently encrypted.
  pub fn is_encrypted(&self) -> bool {
    (self.features & ENCRYPTED_MASK) != 0
  }

  /// Encrypt or decrypt this seed with a password (toggle).
  pub fn crypt(&mut self, password: &str) {
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfkd().collect());
    let mut mask = Zeroizing::new([0u8; 32]);
    let mut salt = [0u8; 16];
    salt[.. 13].copy_from_slice(b"POLYSEED mask");
    // salt[13] stays 0x00
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    pbkdf2_hmac::<Sha256>(
      normalized.as_bytes(),
      &salt,
      POLYSEED_CRYPT_ITERATIONS,
      mask.as_mut(),
    );

    for i in 0 .. SECRET_SIZE {
      self.entropy[i] ^= mask[i];
    }
    self.entropy[SECRET_SIZE - 1] &= LAST_BYTE_SECRET_BITS_MASK;

    self.features ^= ENCRYPTED_MASK;
    self.checksum = poly_eval(&*self.to_poly());
  }

  /// This seed's entropy.
  pub fn entropy(&self) -> &Zeroizing<[u8; 32]> {
    &self.entropy
  }

  /// The key derived from this seed.
  pub fn key(&self, coin: Coin) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut salt = [0u8; 32];
    salt[.. 12].copy_from_slice(POLYSEED_SALT);
    salt[13] = 0xFF;
    salt[14] = 0xFF;
    salt[15] = 0xFF;
    salt[16 .. 20].copy_from_slice(&u32::from(coin.to_raw()).to_le_bytes());
    salt[20 .. 24].copy_from_slice(&u32::from(self.birthday).to_le_bytes());
    salt[24 .. 28].copy_from_slice(&u32::from(self.features).to_le_bytes());
    pbkdf2_hmac::<Sha256>(self.entropy.as_slice(), &salt, POLYSEED_KEYGEN_ITERATIONS, key.as_mut());
    key
  }

  /// The String representation of this seed.
  pub fn to_string(&self, coin: Coin) -> Zeroizing<String> {
    // Encode the polynomial with the existing checksum
    let mut poly = self.to_poly();
    poly[0] = self.checksum;

    // Embed the coin
    poly[POLY_NUM_CHECK_DIGITS] ^= coin.to_raw();

    // Output words with language-specific separator
    let lang_wl = &LANGUAGES[&self.language];
    let mut seed = Zeroizing::new(String::new());
    for i in 0 .. poly.len() {
      seed.push_str(lang_wl.words[usize::from(poly[i])]);
      if i < poly.len() - 1 {
        seed.push_str(lang_wl.separator);
      }
    }

    // Apply NFC composition if required by the language
    if lang_wl.compose {
      let composed: String = seed.nfc().collect();
      seed.zeroize();
      seed = Zeroizing::new(composed);
    }

    seed
  }

  /// Serialize this seed to a 32-byte binary format.
  pub fn store(&self) -> Zeroizing<[u8; 32]> {
    let mut storage = Zeroizing::new([0u8; 32]);
    storage[.. 8].copy_from_slice(STORAGE_HEADER);
    let v1 = (u16::from(self.features) << DATE_BITS) | self.birthday;
    storage[8 .. 10].copy_from_slice(&v1.to_le_bytes());
    storage[10 .. 10 + SECRET_SIZE].copy_from_slice(&self.entropy[.. SECRET_SIZE]);
    storage[29] = STORAGE_EXTRA_BYTE;
    let v2 = STORAGE_FOOTER | self.checksum;
    storage[30 .. 32].copy_from_slice(&v2.to_le_bytes());
    storage
  }

  /// Deserialize a seed from a 32-byte binary format. Accepts encrypted seeds.
  pub fn load(storage: &[u8; 32], language: Language, enabled_features: u8) -> Result<Polyseed, PolyseedError> {
    if storage[.. 8] != *STORAGE_HEADER {
      return Err(PolyseedError::InvalidFormat);
    }

    let v1 = u16::from_le_bytes([storage[8], storage[9]]);
    let birthday = v1 & DATE_MASK;
    let features_raw = v1 >> DATE_BITS;
    if features_raw > u16::from(FEATURE_MASK) {
      return Err(PolyseedError::InvalidFormat);
    }
    let features = features_raw as u8;

    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy[.. SECRET_SIZE].copy_from_slice(&storage[10 .. 10 + SECRET_SIZE]);
    if entropy[SECRET_SIZE - 1] & !LAST_BYTE_SECRET_BITS_MASK != 0 {
      return Err(PolyseedError::InvalidFormat);
    }

    if storage[29] != STORAGE_EXTRA_BYTE {
      return Err(PolyseedError::InvalidFormat);
    }

    let v2 = u16::from_le_bytes([storage[30], storage[31]]);
    let stored_checksum = v2 & GF_MASK;
    let footer = v2 & !GF_MASK;
    if footer != STORAGE_FOOTER {
      return Err(PolyseedError::InvalidFormat);
    }

    if !polyseed_features_supported(features, enabled_features) {
      return Err(PolyseedError::UnsupportedFeatures);
    }

    let seed = Polyseed {
      language,
      birthday,
      features,
      entropy,
      checksum: stored_checksum,
    };

    let mut poly = seed.to_poly();
    poly[0] = stored_checksum;
    if poly_eval(&poly) != 0 {
      return Err(PolyseedError::InvalidChecksum);
    }

    Ok(seed)
  }
}
