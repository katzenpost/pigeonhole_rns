//! Query and reply encodings, byte for byte those of `wire.py`, shared by Reticulum requests,
//! Channel frames and the bridge socket.
//!
//! A query is one byte, 0 for a read and 1 for a write, the 32 byte Box ID, and for a write the
//! 64 byte signature and the ciphertext; a tombstone has an empty ciphertext. A reply is one
//! result byte, a Pigeonhole replica error code, and for a found box the signature and
//! ciphertext.

use std::io::{self, Read, Write};

pub const READ: u8 = 0;
pub const WRITE: u8 = 1;
pub const BOX_ID_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

// Pigeonhole replica error codes, as in pigeonhole/errors.go.
pub const SUCCESS: u8 = 0;
pub const NOT_FOUND: u8 = 1;
pub const INVALID_BOX_ID: u8 = 2;
pub const INVALID_SIGNATURE: u8 = 3;
pub const INVALID_PAYLOAD: u8 = 5;
pub const ALREADY_EXISTS: u8 = 10;
pub const TOMBSTONE: u8 = 11;

pub type BoxId = [u8; BOX_ID_SIZE];

/// A bridge announces the mixnet it serves as the first 16 bytes of the SHA-256 of a name its
/// operator gives; bridges with the same id serve one mixnet. A replica forwarding a box pulled
/// from a mixnet prefixes the write with that id, on path `forward`.
pub const MIXNET_ID_SIZE: usize = 16;

pub fn mixnet_id(name: &str) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(name.as_bytes())[..MIXNET_ID_SIZE].to_vec()
}

/// Codes that mean the receiver holds the box after a write.
pub fn stored(code: u8) -> bool {
    code == SUCCESS || code == ALREADY_EXISTS
}

#[derive(Debug, PartialEq, Eq)]
pub enum Query {
    Read(BoxId),
    Write { box_id: BoxId, signature: Vec<u8>, ciphertext: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: u8,
    /// The signature and ciphertext of a found box.
    pub found: Option<(Vec<u8>, Vec<u8>)>,
}

impl Reply {
    pub fn code(code: u8) -> Reply {
        Reply { code, found: None }
    }
}

pub fn encode_read(box_id: &BoxId) -> Vec<u8> {
    [&[READ][..], box_id].concat()
}

pub fn encode_write(box_id: &BoxId, signature: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    [&[WRITE][..], box_id, signature, ciphertext].concat()
}

pub fn decode_query(data: &[u8]) -> Option<Query> {
    if data.len() < 1 + BOX_ID_SIZE {
        return None;
    }
    let box_id: BoxId = data[1..1 + BOX_ID_SIZE].try_into().unwrap();
    let rest = &data[1 + BOX_ID_SIZE..];
    match data[0] {
        READ if rest.is_empty() => Some(Query::Read(box_id)),
        WRITE if rest.len() >= SIGNATURE_SIZE => Some(Query::Write {
            box_id,
            signature: rest[..SIGNATURE_SIZE].to_vec(),
            ciphertext: rest[SIGNATURE_SIZE..].to_vec(),
        }),
        _ => None,
    }
}

pub fn encode_reply(r: &Reply) -> Vec<u8> {
    match &r.found {
        Some((sig, ct)) if r.code == SUCCESS => [&[r.code][..], sig, ct].concat(),
        _ => vec![r.code],
    }
}

pub fn decode_reply(data: &[u8]) -> Option<Reply> {
    let (&code, rest) = data.split_first()?;
    if code == SUCCESS && !rest.is_empty() {
        if rest.len() < SIGNATURE_SIZE {
            return None;
        }
        let (sig, ct) = rest.split_at(SIGNATURE_SIZE);
        return Some(Reply { code, found: Some((sig.to_vec(), ct.to_vec())) });
    }
    Some(Reply::code(code))
}

/// The most entries in a sync page.
pub const SYNC_PAGE: usize = 128;

/// A sync page: a head (two Box IDs for a query, the range it covers, exclusive below and
/// inclusive above; one for a reply, where the reply's page ends), then up to [`SYNC_PAGE`]
/// entries of a Box ID and a byte, 1 for a tombstone.
pub fn encode_sync(head: &[u8], entries: &[(BoxId, bool)]) -> Vec<u8> {
    let mut out = head.to_vec();
    for (b, tomb) in entries {
        out.extend_from_slice(b);
        out.push(*tomb as u8);
    }
    out
}

/// A sync page's head, and its entries of a Box ID and whether it is a tombstone.
pub type SyncPage = (Vec<u8>, Vec<(BoxId, bool)>);

pub fn decode_sync(data: &[u8], head_len: usize) -> Option<SyncPage> {
    let step = BOX_ID_SIZE + 1;
    if data.len() < head_len {
        return None;
    }
    let body = &data[head_len..];
    if !body.len().is_multiple_of(step) || body.len() / step > SYNC_PAGE {
        return None;
    }
    let entries = body
        .chunks(step)
        .map(|c| (c[..BOX_ID_SIZE].try_into().unwrap(), c[BOX_ID_SIZE] == 1))
        .collect();
    Some((data[..head_len].to_vec(), entries))
}

/// The bridge socket's largest frame.
pub const MAX_FRAME: usize = 1 << 20;

/// A bridge socket message: a big endian u32 length, then the payload.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    w.write_all(&[&(payload.len() as u32).to_be_bytes()[..], payload].concat())
}

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame length {n} out of range")));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/bridge_socket_vectors.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn hx(v: &Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    fn framed(p: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, p).unwrap();
        out
    }

    #[test]
    fn query_vectors() {
        for v in vectors()["queries"].as_array().unwrap() {
            let box_id: BoxId = hx(v, "box_id").try_into().unwrap();
            let (payload, want) = if v["kind"] == READ {
                (encode_read(&box_id), Query::Read(box_id))
            } else {
                let (s, c) = (hx(v, "signature"), hx(v, "ciphertext"));
                (encode_write(&box_id, &s, &c), Query::Write { box_id, signature: s, ciphertext: c })
            };
            assert_eq!(payload, hx(v, "payload"), "{}", v["name"]);
            assert_eq!(framed(&payload), hx(v, "frame"));
            assert_eq!(read_frame(&mut &framed(&payload)[..]).unwrap(), payload);
            assert_eq!(decode_query(&payload), Some(want));
        }
    }

    #[test]
    fn reply_vectors() {
        for v in vectors()["replies"].as_array().unwrap() {
            let found = v.get("signature").map(|_| (hx(v, "signature"), hx(v, "ciphertext")));
            let r = Reply { code: v["code"].as_u64().unwrap() as u8, found };
            let payload = encode_reply(&r);
            assert_eq!(payload, hx(v, "payload"), "{}", v["name"]);
            assert_eq!(framed(&payload), hx(v, "frame"));
            assert_eq!(decode_reply(&payload), Some(r));
        }
    }

    #[test]
    fn malformed_vectors() {
        for v in vectors()["malformed"].as_array().unwrap() {
            assert_eq!(decode_query(&hx(v, "payload")), None, "{}", v["name"]);
        }
        for bad in [&b""[..], &[0; 32], &[7; 33], &[1; 41]] {
            assert_eq!(decode_query(bad), None);
        }
    }

    #[test]
    fn box_vectors() {
        let dir = tempfile::tempdir().unwrap();
        for v in vectors()["boxes"].as_array().unwrap() {
            let size = v["ciphertext_size"].as_u64().map(|n| n as usize);
            let e = crate::engine::Engine::new(
                crate::store::Store::open(&dir.path().join("v.sqlite")).unwrap(),
                [1; 16],
                [2; 16],
                size,
                false,
                crate::engine::Mode::Open,
            );
            let q = Query::Write {
                box_id: hx(v, "box_id").try_into().unwrap(),
                signature: hx(v, "signature"),
                ciphertext: hx(v, "ciphertext"),
            };
            assert_eq!(e.verify(&q) as u64, v["expect"].as_u64().unwrap(), "{}", v["name"]);
        }
    }

    #[test]
    fn sync_pages() {
        let e = [([7; 32], true), ([9; 32], false)];
        let raw = encode_sync(&[1; 64], &e);
        assert_eq!(decode_sync(&raw, 64), Some((vec![1; 64], e.to_vec())));
        assert_eq!(decode_sync(&raw[..raw.len() - 1], 64), None);
        assert_eq!(decode_sync(&encode_sync(&[0; 32], &vec![([0; 32], false); 129]), 32), None);
    }
}
