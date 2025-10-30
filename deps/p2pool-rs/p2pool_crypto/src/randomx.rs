// P2Pool for Monero - RandomX PoW interface
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// RandomX is Monero's proof-of-work algorithm. The seed hash changes every
// 2048 blocks with a 64-block lag. p2pool must verify that each share's PoW
// meets the sidechain difficulty before broadcasting it to peers.

use crate::Hash;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RandomXError {
    #[error("failed to allocate RandomX cache: {0}")]
    CacheAlloc(String),
    #[error("failed to allocate RandomX VM: {0}")]
    VmAlloc(String),
    #[error("hash computation failed: {0}")]
    HashError(String),
    #[error("unexpected hash output size")]
    BadHashSize,
}

impl From<randomx_rs::RandomXError> for RandomXError {
    fn from(e: randomx_rs::RandomXError) -> Self {
        RandomXError::HashError(e.to_string())
    }
}

/// Flags controlling RandomX mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomXMode {
    /// Light mode: uses cache only (~256 MB RAM), slower hash rate.
    Light,
    /// Full mode: allocates the full dataset (~2.5 GB RAM), faster hash rate.
    Full,
}

/// A RandomX virtual machine for a single seed epoch.
///
/// All hashing for a given epoch should reuse the same `RandomXHasher`.
/// Creating a new one is expensive (cache / dataset initialisation).
///
/// The VM is protected by a `Mutex` because `RandomXVM` is `Send` but not
/// `Sync` (it may alter the thread-local FP rounding mode). For high-
/// throughput verification, replace the `Mutex<RandomXVM>` with a
/// `thread_local::ThreadLocal<RandomXVM>` backed by a shared `RandomXCache`
/// (see the cuprate project for that pattern).
pub struct RandomXHasher {
    seed: Hash,
    mode: RandomXMode,
    /// Shared cache; kept alive as long as the hasher exists.
    _cache: RandomXCache,
    /// The RandomX VM, locked for exclusive access per hash call.
    vm: Mutex<RandomXVM>,
}

impl RandomXHasher {
    /// Initialise a new hasher for the given seed hash.
    ///
    /// This allocates and initialises the RandomX cache (~256 MB for light
    /// mode). Call once per epoch change, then reuse for all hashes in that
    /// epoch.
    pub fn new(seed: Hash, mode: RandomXMode) -> Result<Self, RandomXError> {
        let mut flags = RandomXFlag::get_recommended_flags();
        if mode == RandomXMode::Full {
            flags = flags | RandomXFlag::FLAG_FULL_MEM;
        }

        let cache = RandomXCache::new(flags, seed.as_bytes().as_slice())
            .map_err(|e| RandomXError::CacheAlloc(e.to_string()))?;

        let vm = RandomXVM::new(flags, Some(cache.clone()), None)
            .map_err(|e| RandomXError::VmAlloc(e.to_string()))?;

        Ok(Self {
            seed,
            mode,
            _cache: cache,
            vm: Mutex::new(vm),
        })
    }

    /// Compute the RandomX hash of `data`.
    ///
    /// Returns the 256-bit hash, or an error if the VM is poisoned or
    /// the underlying library reports a failure.
    pub fn hash(&self, data: &[u8]) -> Result<Hash, RandomXError> {
        let vm = self.vm.lock().expect("RandomX VM mutex poisoned");
        let out = vm
            .calculate_hash(data)
            .map_err(|e| RandomXError::HashError(e.to_string()))?;
        Hash::from_bytes(&out).ok_or(RandomXError::BadHashSize)
    }

    pub fn seed(&self) -> Hash {
        self.seed
    }

    pub fn mode(&self) -> RandomXMode {
        self.mode
    }
}

// SAFETY: RandomXHasher is Send because all interior state is either Send
// (RandomXCache, the seed bytes) or guarded by a Mutex (RandomXVM).
// The Mutex itself makes the whole struct Sync.
unsafe impl Send for RandomXHasher {}
unsafe impl Sync for RandomXHasher {}

/// Return the seed block height for a given chain height.
///
/// Monero uses a 2-epoch lag: the seed at height H was committed at
/// `floor(H / 2048) * 2048 - 64` (for H >= 2112), clamped to 0.
pub fn get_seed_height(height: u64) -> u64 {
    const EPOCH: u64 = 2048;
    const LAG: u64 = 64;
    if height < EPOCH + LAG {
        return 0;
    }
    (height / EPOCH) * EPOCH - LAG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_height_boundaries() {
        assert_eq!(get_seed_height(0), 0);
        assert_eq!(get_seed_height(2111), 0);
        assert_eq!(get_seed_height(2112), 2048 - 64); // 1984
        assert_eq!(get_seed_height(4096), 4096 - 64); // 4032
    }

    /// Smoke-test: initialise a VM with a zero seed and hash a known input.
    /// The exact output is not checked here (it depends on the RandomX version),
    /// but the call must not panic or return an error.
    #[test]
    fn smoke_hash() {
        let seed = Hash::ZERO;
        let hasher = RandomXHasher::new(seed, RandomXMode::Light)
            .expect("RandomX hasher initialisation failed");
        let h = hasher.hash(b"hello world").expect("hash failed");
        assert!(!h.is_zero(), "RandomX hash of non-empty input should not be zero");
    }
}
