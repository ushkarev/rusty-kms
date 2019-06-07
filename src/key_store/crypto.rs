use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::{Formatter, Result as FormatResult};
use std::num::NonZeroU32;

use base64::{decode as b64decode, encode as b64encode};
use ring::aead::{SealingKey, seal_in_place, OpeningKey, open_in_place, AES_256_GCM, Nonce, Aad};
use ring::digest;
use ring::pbkdf2::derive as pbkdf2_derive;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Deserializer, Serializer};
use serde::de;
use serde::ser::SerializeSeq;

use crate::key_store::errors::*;

// length of key material for AES_256_GCM
const KEY_MATERIAL_LEN: usize = 32;  // AES_256_GCM.key_len()
// length to extend encrypted data for AES_256_GCM
const TAG_LEN: usize = 16;  // AES_256_GCM.tag_len()
// length of AES_256_GCM nonce
const NONCE_LEN: usize = 12;  // AES_256_GCM.nonce_len()

pub const MIN_ENCRYPTED_DATA_LEN: usize = TAG_LEN + NONCE_LEN;

pub type KeyMaterial = [u8; KEY_MATERIAL_LEN];

pub fn make_key_material() -> KeyMaterial {
    let mut key_material = [0u8; KEY_MATERIAL_LEN];
    SystemRandom::new().fill(&mut key_material).expect("unable to generate key material");
    key_material
}

pub fn derive_key_material(password: &str) -> KeyMaterial {
    // NB: SHA256_OUTPUT_LEN = AES_256_GCM.key_len()
    static SALT: &[u8; 16] = b"*h\xea\x8c\xc8;\x88]\r\xfc\x1c\xa8z{\xb4\x85";
    let mut key = [0u8; KEY_MATERIAL_LEN];
    pbkdf2_derive(&digest::SHA256, NonZeroU32::new(120_000).unwrap(), SALT, password.as_bytes(), &mut key);
    key
}

pub fn deserialise_key_materials<'de, D>(deserializer: D) -> Result<Vec<KeyMaterial>, D::Error> where D: Deserializer<'de> {
    struct V;

    impl<'de> de::Visitor<'de> for V {
        type Value = Vec<KeyMaterial>;

        fn expecting(&self, formatter: &mut Formatter) -> FormatResult {
            formatter.write_str("seq expected")
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error> where A: de::SeqAccess<'de> {
            let seq: Vec<String> = Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
            let mut key_materials: Self::Value = Vec::with_capacity(seq.len());
            for item in seq.iter() {
                let item = b64decode(item)
                    .map_err(de::Error::custom)?;
                let msg = format!("sequence of {} bytes", KEY_MATERIAL_LEN);
                let key_material = item.as_slice().try_into()
                    .map_err(|_| de::Error::invalid_length(item.len(), &msg.as_str()))?;
                key_materials.push(key_material);
            }
            Ok(key_materials)
        }
    }

    deserializer.deserialize_seq(V)
}

pub fn serialise_key_materials<S>(key_materials: &[KeyMaterial], serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
    let mut seq = serializer.serialize_seq(Some(key_materials.len()))?;
    for item in key_materials.iter().map(b64encode) {
        seq.serialize_element(&item)?;
    }
    seq.end()
}

fn aad_from_context(context: &HashMap<&str, &str>) -> Vec<u8> {
    if context.is_empty() {
        return Vec::new();
    }
    let mut capacity: usize = 0;
    let mut context: Vec<(&[u8], &[u8])> = context.iter()
        .map(|(&k, &v)| {
            let k = k.as_bytes();
            let v = v.as_bytes();
            capacity += 2 + k.len() + v.len();
            (k, v)
        })
        .collect();
    context.sort_by(|&(k1, _), &(k2, _)| k1.cmp(&k2));
    context.iter()
        .fold(Vec::with_capacity(capacity), |mut context, &(k, v)| {
            context.push(b'\x01');
            context.extend_from_slice(k);
            context.push(b'\x02');
            context.extend_from_slice(v);
            context
        })
}

pub fn raw_decrypt(data: &mut Vec<u8>, key: &KeyMaterial, context: &HashMap<&str, &str>) -> Result<(), RawDecryptError> {
    // NB: data must end with tag and nonce
    let len = data.len();
    if len < TAG_LEN + NONCE_LEN {
        return Err(RawDecryptError::Length);
    }
    let nonce_offset = len - NONCE_LEN;
    let (cipher_text, nonce) = data.split_at_mut(nonce_offset);
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .or(Err(RawDecryptError::InvalidNonce))?;
    let opening_key = OpeningKey::new(&AES_256_GCM, key)
        .or(Err(RawDecryptError::InvalidKey))?;
    let aad = aad_from_context(&context);
    let aad = Aad::from(&aad);
    open_in_place(&opening_key, nonce, aad, 0, cipher_text)
        .or(Err(RawDecryptError::Error))?;
    data.drain(nonce_offset - TAG_LEN..);
    Ok(())
}

pub fn raw_encrypt(data: &mut Vec<u8>, key: &KeyMaterial, context: &HashMap<&str, &str>) -> Result<(), RawEncryptError> {
    // NB: extends data with tag and nonce
    static TAG_SPACE: [u8; TAG_LEN] = [0u8; TAG_LEN];
    data.extend_from_slice(&TAG_SPACE);
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).expect("cannot generate nonce");
    let sealing_key = SealingKey::new(&AES_256_GCM, key)
        .or(Err(RawEncryptError::InvalidKey))?;
    let aad = aad_from_context(&context);
    let aad = Aad::from(&aad);
    seal_in_place(&sealing_key, Nonce::assume_unique_for_key(nonce), aad, data, TAG_LEN)
        .or(Err(RawEncryptError::Error))?;
    data.extend_from_slice(&nonce);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = b"12345678901234567890123456789012";
        let plain_text = b"Plain text data";

        let empty_context = HashMap::new();
        let mut data = plain_text.to_vec();
        assert!(raw_encrypt(&mut data, key, &empty_context).is_ok());
        assert_ne!(&data, b"Plain text data");
        assert_ne!(data.len(), plain_text.len());
        assert!(raw_decrypt(&mut data, key, &empty_context).is_ok());
        assert_eq!(&data, b"Plain text data");

        let mut context = HashMap::new();
        context.insert("name", "123");
        let mut data = plain_text.to_vec();
        assert!(raw_encrypt(&mut data, key, &context).is_ok());
        assert_ne!(&data, b"Plain text data");
        assert_ne!(data.len(), plain_text.len());
        assert!(raw_decrypt(&mut data, key, &context).is_ok());
        assert_eq!(&data, b"Plain text data");

        let mut data = plain_text.to_vec();
        assert!(raw_encrypt(&mut data, key, &context).is_ok());
        assert!(raw_decrypt(&mut data, key, &empty_context).is_err());
        let mut data = plain_text.to_vec();
        assert!(raw_encrypt(&mut data, key, &empty_context).is_ok());
        assert!(raw_decrypt(&mut data, key, &context).is_err());
    }
}
