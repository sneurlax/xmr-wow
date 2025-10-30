// P2Pool for Monero - ZMQ reader for monerod
// Copyright (c) 2024 p2pool-rs Developers
// SPDX-License-Identifier: GPL-3.0-only
//
// monerod publishes block-related events over ZMQ:
//
//   Topic "json-minimal-txpool_add":  new mempool transactions
//   Topic "json-minimal-chain_main":  new main-chain block
//   Topic "json-miner-data":          new miner data (height, prev_id, seed, diff, txpool)
//   Topic "json-full-chain_main":     full serialized main-chain block
//
// p2pool primarily uses "json-miner-data" to trigger block-template updates,
// and "json-minimal-txpool_add" to maintain the local mempool mirror.
//
// This corresponds to the C++ `ZMQReader` class in zmq_reader.{h,cpp}.

pub mod reader;

pub use reader::ZmqReader;
