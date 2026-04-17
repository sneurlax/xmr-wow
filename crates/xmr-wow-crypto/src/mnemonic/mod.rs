//! Monero/Wownero mnemonic seed support.
//!
//! Supports two formats:
//! - **Classic** (24/25 words): CryptoNote format, 1626-word English list.
//!   The mnemonic directly encodes the 32-byte private spend key.
//! - **Polyseed** (16 words): BIP39-based, 2048-word list.
//!   The key is derived via PBKDF2 with coin-specific salt (Monero vs Wownero).
//!
//! The view key is derived deterministically via `derive_view_key()` in both cases.
//!
//! Auto-detection: `mnemonic_to_scalar` counts words and dispatches accordingly.
//! For polyseed, a `SeedCoin` must be specified since key derivation is coin-specific.

use std::collections::HashMap;
use std::sync::LazyLock;

use crc::{Crc, CRC_32_ISO_HDLC};
use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

// --- Classic seed constants ---
const SEED_LENGTH: usize = 24;
const SEED_LENGTH_WITH_CHECKSUM: usize = 25;
const UNIQUE_PREFIX_LEN: usize = 3;
const POLYSEED_LENGTH: usize = 16;

/// Coin type for polyseed key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedCoin {
    Monero,
    Wownero,
}

struct WordList {
    words: Vec<&'static str>,
    trimmed_map: HashMap<String, usize>,
}

static ENGLISH: LazyLock<WordList> = LazyLock::new(|| {
    let words: Vec<&'static str> = include!("en.rs");
    let mut trimmed_map = HashMap::with_capacity(words.len());
    for (i, word) in words.iter().enumerate() {
        let trimmed: String = word.chars().take(UNIQUE_PREFIX_LEN).collect();
        trimmed_map.insert(trimmed, i);
    }
    WordList { words, trimmed_map }
});

fn trim(word: &str) -> String {
    word.chars().take(UNIQUE_PREFIX_LEN).collect()
}

fn checksum_index(words: &[String]) -> usize {
    let trimmed: String = words.iter().map(|w| trim(w)).collect();
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut digest = crc.digest();
    digest.update(trimmed.as_bytes());
    (digest.finalize() as usize) % words.len()
}

/// Convert a mnemonic string to a private spend key Scalar.
///
/// Auto-detects format by word count:
/// - 16 words: Polyseed (requires `coin` parameter)
/// - 24/25 words: Classic CryptoNote
///
/// For classic seeds, `coin` is ignored.
pub fn mnemonic_to_scalar(mnemonic: &str, coin: SeedCoin) -> Result<Scalar, CryptoError> {
    let word_count = mnemonic.split_whitespace().count();
    match word_count {
        POLYSEED_LENGTH => polyseed_to_scalar(mnemonic, coin),
        SEED_LENGTH | SEED_LENGTH_WITH_CHECKSUM => classic_mnemonic_to_scalar(mnemonic),
        n => Err(CryptoError::MnemonicError(format!(
            "expected 16, 24, or 25 words, got {}",
            n
        ))),
    }
}

/// Convert a 16-word polyseed mnemonic to a private spend key Scalar.
fn polyseed_to_scalar(mnemonic: &str, coin: SeedCoin) -> Result<Scalar, CryptoError> {
    let ps_coin = match coin {
        SeedCoin::Monero => polyseed::Coin::Monero,
        SeedCoin::Wownero => polyseed::Coin::Wownero,
    };

    let seed = polyseed::Polyseed::from_string(
        polyseed::Language::English,
        Zeroizing::new(mnemonic.to_string()),
        ps_coin,
        0, // no special features enabled
    )
    .map_err(|e| CryptoError::MnemonicError(format!("polyseed: {:?}", e)))?;

    let key_bytes = seed.key(ps_coin);
    let scalar = Scalar::from_bytes_mod_order(*key_bytes);
    Ok(scalar)
}

/// Convert a 24/25-word classic mnemonic to a private spend key Scalar.
fn classic_mnemonic_to_scalar(mnemonic: &str) -> Result<Scalar, CryptoError> {
    let words: Vec<String> = mnemonic
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect();

    let lang = &*ENGLISH;

    // Resolve word indices via trimmed prefix matching
    let mut indices = Vec::with_capacity(words.len());
    for word in &words {
        let trimmed = trim(word);
        match lang.trimmed_map.get(&trimmed) {
            Some(&idx) => indices.push(idx),
            None => {
                return Err(CryptoError::MnemonicError(format!(
                    "unknown word: '{}'",
                    word
                )));
            }
        }
    }

    // Validate checksum if 25 words
    if words.len() == SEED_LENGTH_WITH_CHECKSUM {
        let check_idx = checksum_index(&words[..SEED_LENGTH]);
        let expected_trimmed = trim(&words[check_idx]);
        let actual_trimmed = trim(&words[SEED_LENGTH]);
        if expected_trimmed != actual_trimmed {
            return Err(CryptoError::MnemonicError("invalid checksum".into()));
        }
    }

    // Convert word indices to bytes: 3 words -> 4 bytes, 8 groups -> 32 bytes
    let mut bytes = [0u8; 32];
    let list_len = lang.words.len();

    for i in 0..8 {
        let i3 = i * 3;
        let w1 = indices[i3];
        let w2 = indices[i3 + 1];
        let w3 = indices[i3 + 2];

        let val = w1
            + list_len * ((list_len - w1 + w2) % list_len)
            + list_len * list_len * ((list_len - w2 + w3) % list_len);

        if val % list_len != w1 {
            return Err(CryptoError::MnemonicError("word index mismatch".into()));
        }

        let pos = i * 4;
        bytes[pos..pos + 4].copy_from_slice(&(val as u32).to_le_bytes());
    }

    let scalar =
        Scalar::from_canonical_bytes(bytes)
            .into_option()
            .ok_or(CryptoError::MnemonicError(
                "seed bytes are not a canonical scalar".into(),
            ))?;

    bytes.zeroize();
    Ok(scalar)
}

/// Convert a private spend key Scalar to a 25-word mnemonic string (English, classic format).
pub fn scalar_to_mnemonic(scalar: &Scalar) -> String {
    let bytes = scalar.to_bytes();
    let lang = &*ENGLISH;
    let list_len = lang.words.len() as u64;

    let mut seed_words: Vec<String> = Vec::with_capacity(25);

    for i in 0..8 {
        let pos = i * 4;
        let mut segment = [0u8; 4];
        segment.copy_from_slice(&bytes[pos..pos + 4]);
        let val = u64::from(u32::from_le_bytes(segment));

        let w1 = val % list_len;
        let w2 = ((val / list_len) + w1) % list_len;
        let w3 = ((val / list_len / list_len) + w2) % list_len;

        seed_words.push(lang.words[w1 as usize].to_string());
        seed_words.push(lang.words[w2 as usize].to_string());
        seed_words.push(lang.words[w3 as usize].to_string());
    }

    // Checksum: the word at index (CRC32 % 24) is repeated as word 25
    let check_idx = checksum_index(&seed_words);
    seed_words.push(seed_words[check_idx].clone());

    seed_words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip_random_scalar() {
        let scalar = Scalar::random(&mut OsRng);
        let mnemonic = scalar_to_mnemonic(&scalar);
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 25, "mnemonic should be 25 words");

        let recovered = mnemonic_to_scalar(&mnemonic, SeedCoin::Monero).unwrap();
        assert_eq!(scalar, recovered, "roundtrip should preserve scalar");
    }

    #[test]
    fn roundtrip_multiple() {
        for _ in 0..10 {
            let scalar = Scalar::random(&mut OsRng);
            let mnemonic = scalar_to_mnemonic(&scalar);
            let recovered = mnemonic_to_scalar(&mnemonic, SeedCoin::Monero).unwrap();
            assert_eq!(scalar, recovered);
        }
    }

    #[test]
    fn rejects_bad_checksum() {
        let scalar = Scalar::random(&mut OsRng);
        let mnemonic = scalar_to_mnemonic(&scalar);
        let mut words: Vec<&str> = mnemonic.split_whitespace().collect();
        words[24] = "abbey";
        let bad = words.join(" ");
        assert!(mnemonic_to_scalar(&bad, SeedCoin::Monero).is_err());
    }

    #[test]
    fn rejects_unknown_word() {
        let result = mnemonic_to_scalar("zzzzfake abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey", SeedCoin::Monero);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(mnemonic_to_scalar("abbey abbey abbey", SeedCoin::Monero).is_err());
    }

    #[test]
    fn polyseed_wownero_parses() {
        // A valid Wownero polyseed should parse without error
        let result = mnemonic_to_scalar(
            "border artist novel snap topic appear flat coast silk long large angry panther lottery slow false",
            SeedCoin::Wownero,
        );
        assert!(result.is_ok(), "polyseed should parse: {:?}", result.err());
    }
}
