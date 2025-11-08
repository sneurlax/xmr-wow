use polyseed::{get_feature, Coin, Language, Polyseed, PolyseedError};
use zeroize::Zeroizing;

#[test]
fn bug_word_count_panics_on_overflow() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language extra";
  let res = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0);
  assert_eq!(res, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn bug_word_count_accepts_too_few() {
  let seed = "raven tail swear";
  let res = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0);
  assert_eq!(res, Err(PolyseedError::InvalidWordCount));
}

#[test]
fn bug_accent_strip_uses_ascii_filter() {
  use unicode_normalization::UnicodeNormalization;

  let ascii_seed = "eje fin parte celebre tabu pestana lienzo puma \
    prision hora regalo lengua existir lapiz lote sonoro";
  let res = Polyseed::from_string(Language::Spanish, Zeroizing::new(ascii_seed.into()), Coin::Monero, 0);
  assert!(res.is_ok());

  let nfc_seed: String = "eje fin parte celebre tabu pestana lienzo puma \
    prision hora regalo lengua existir lapiz lote sonoro"
    .nfc()
    .collect();
  let res_nfc = Polyseed::from_string(Language::Spanish, Zeroizing::new(nfc_seed), Coin::Monero, 0);
  assert!(res_nfc.is_ok());
}

#[test]
fn bug_poly_arrays_not_zeroized() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let _seed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
}

#[test]
fn gap_no_multi_coin_support() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let parsed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  let key_monero = parsed.key(Coin::Monero);
  let key_aeon = parsed.key(Coin::Aeon);
  let key_wownero = parsed.key(Coin::Wownero);
  assert_ne!(key_monero, key_aeon);
  assert_ne!(key_monero, key_wownero);
  assert_ne!(key_aeon, key_wownero);
}

#[test]
fn gap_no_is_encrypted() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let parsed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  assert!(!parsed.is_encrypted());
}

#[test]
fn gap_no_crypt() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let mut parsed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  assert!(!parsed.is_encrypted());
  parsed.crypt("test_password");
  assert!(parsed.is_encrypted());
  parsed.crypt("test_password");
  assert!(!parsed.is_encrypted());
}

#[test]
fn gap_no_store_load() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let parsed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  let storage = parsed.store();
  let loaded = Polyseed::load(&storage, Language::English, 0).unwrap();
  assert_eq!(parsed, loaded);
}

#[test]
fn gap_no_auto_detect() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let (parsed, lang) = Polyseed::from_string_auto(Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  assert_eq!(lang, Language::English);
  let expected = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  assert_eq!(parsed, expected);
}

#[test]
fn gap_no_enable_features() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let parsed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  assert_eq!(get_feature(parsed.features(), 1), 0);
  assert_eq!(get_feature(parsed.features(), 2), 0);
  assert_eq!(get_feature(parsed.features(), 4), 0);
}

#[test]
fn gap_no_nfc_output() {
  let seed = "raven tail swear infant grief assist regular lamp \
    duck valid someone little harsh puppy airport language";
  let parsed = Polyseed::from_string(Language::English, Zeroizing::new(seed.into()), Coin::Monero, 0).unwrap();
  let output = parsed.to_string(Coin::Monero);
  let ascii_spaces = output.chars().filter(|&c| c == ' ').count();
  assert_eq!(ascii_spaces, 15);
}
