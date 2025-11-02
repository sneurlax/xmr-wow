// xmr-wow-sharechain: Monero variable-length integer (LEB128) encoding
// Ported verbatim from deps/p2pool-rs/p2pool_monero/src/varint.rs
// Copyright (c) 2024 p2pool-rs Developers  (original)
// SPDX-License-Identifier: GPL-3.0-only

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VarIntError {
    #[error("unexpected end of input")]
    UnexpectedEnd,
    #[error("varint overflow: value exceeds u64")]
    Overflow,
}

/// Encode `value` as a Monero varint, appending bytes to `out`.
pub fn encode(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

/// Encode `value` as a varint and return the bytes.
pub fn encode_to_vec(value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    encode(value, &mut buf);
    buf
}

/// Decode a Monero varint from `data`, returning `(value, bytes_consumed)`.
pub fn decode(data: &[u8]) -> Result<(u64, usize), VarIntError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return Err(VarIntError::Overflow);
        }
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(VarIntError::UnexpectedEnd)
}

/// Return the number of bytes needed to encode `value`.
pub fn encoded_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        for v in [0u64, 1, 127, 128, 16383, 16384, u64::MAX] {
            let encoded = encode_to_vec(v);
            let (decoded, n) = decode(&encoded).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, encoded.len());
        }
    }

    #[test]
    fn known_values() {
        // 0 -> [0x00]
        assert_eq!(encode_to_vec(0), vec![0x00]);
        // 127 -> [0x7F]
        assert_eq!(encode_to_vec(127), vec![0x7F]);
        // 128 -> [0x80, 0x01]
        assert_eq!(encode_to_vec(128), vec![0x80, 0x01]);
        // 300 -> [0xAC, 0x02]
        assert_eq!(encode_to_vec(300), vec![0xAC, 0x02]);
    }

    #[test]
    fn encoded_len_matches_actual() {
        for v in [0u64, 1, 127, 128, 16383, 16384, u64::MAX] {
            assert_eq!(encoded_len(v), encode_to_vec(v).len());
        }
    }

    #[test]
    fn decode_overflow_rejected() {
        // 10 continuation bytes then a terminator ; shift reaches 70 bits -> Overflow
        let mut buf = vec![0x80u8; 10];
        buf.push(0x01); // terminator
        assert!(matches!(decode(&buf), Err(VarIntError::Overflow)));
    }

    #[test]
    fn decode_unexpected_end() {
        // Continuation bit set, but no more bytes
        let buf = vec![0x80u8];
        assert!(matches!(decode(&buf), Err(VarIntError::UnexpectedEnd)));
    }
}
