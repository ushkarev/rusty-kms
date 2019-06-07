use std::fmt::{Debug, Formatter, Result as FormatResult};
use std::str;

use crate::key_store::errors::*;
use crate::key_store::crypto::MIN_ENCRYPTED_DATA_LEN;

const WRAPPING_VERSION: u8 = 1;

pub struct WrappedCipherText<'a> {
    pub encrypted_data: &'a [u8],  // NB: ending with tag and nonce
    pub key_arn: &'a str,
    pub key_material_generation: u8,
    pub version: u8,
}

impl<'a> WrappedCipherText<'a> {
    pub fn new(encrypted_data: &'a [u8], key_arn: &'a str, key_material_generation: u8) -> WrappedCipherText<'a> {
        WrappedCipherText {
            encrypted_data,
            key_arn,
            key_material_generation,
            version: 1,
        }
    }

    pub fn unwrap(data: &[u8]) -> Result<WrappedCipherText, UnwrapCipherTextError> {
        let len = data.len();
        if len < 3 {
            return Err(UnwrapCipherTextError::InvalidWrapper);
        }
        let version = data[len - 1];
        let key_material_generation = data[len - 2];
        let key_arn_len = data[len - 3] as usize;
        if version != WRAPPING_VERSION {
            return Err(UnwrapCipherTextError::UnsupportedVersion);
        }
        let len = len - 3;
        let data = &data[..len];
        if len < key_arn_len {
            return Err(UnwrapCipherTextError::InvalidWrapper);
        }
        let key_arn = &data[len - key_arn_len..len];
        let key_arn = match str::from_utf8(key_arn) {
            Ok(key_arn) => key_arn,
            _ => return Err(UnwrapCipherTextError::InvalidWrapper),
        };
        let encrypted_data = &data[..len - key_arn_len];
        if key_arn.is_empty() || encrypted_data.len() < MIN_ENCRYPTED_DATA_LEN {
            return Err(UnwrapCipherTextError::InvalidWrapper);
        }
        Ok(WrappedCipherText {
            encrypted_data,
            key_material_generation,
            key_arn,
            version,
        })
    }

    pub fn wrap(&self) -> Result<Vec<u8>, WrapCipherTextError> {
        if self.encrypted_data.len() < MIN_ENCRYPTED_DATA_LEN {
            return Err(WrapCipherTextError::DataLength);
        }
        let key_arn = self.key_arn.as_bytes();
        let key_arn_len = key_arn.len();
        if key_arn_len > 255 {
            return Err(WrapCipherTextError::ArnLength);
        }
        let encrypted_data_len = self.encrypted_data.len();
        let len = encrypted_data_len + key_arn_len + 3;
        let mut data = Vec::with_capacity(len);
        data.extend_from_slice(self.encrypted_data);
        data.extend_from_slice(key_arn);
        data.extend_from_slice(&[key_arn_len as u8, self.key_material_generation, WRAPPING_VERSION]);
        Ok(data)
    }
}

impl<'a> Debug for WrappedCipherText<'a> {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "WrappedCipherText({})", &self.key_arn)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap() {
        let data = b"encr1234567890123456123456789012arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555\x46\x00\x01";
        let cipher_text = WrappedCipherText::unwrap(data);
        assert!(cipher_text.is_ok());
        let cipher_text = cipher_text.unwrap();
        assert_eq!(cipher_text.version, 1);
        assert_eq!(cipher_text.key_material_generation, 0);
        assert_eq!(cipher_text.key_arn, "arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555");
        assert_eq!(cipher_text.encrypted_data, b"encr1234567890123456123456789012");

        // too short
        let data = b"";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::InvalidWrapper));
        let data = b"\x00\x01";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::InvalidWrapper));
        let data = b"aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555\x46\x00\x01";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::InvalidWrapper));

        // unsupported version
        let data = b"encr1234567890123456123456789012arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555\x46\x00\x00";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::UnsupportedVersion));
        let data = b"encr1234567890123456123456789012arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555\x46\x00\x0e";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::UnsupportedVersion));

        // no encrypted data tag or nonce
        let data = b"123456789012345123456789012arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555\x46\x00\x01";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::InvalidWrapper));
        let data = b"123456789012arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555\x46\x00\x01";
        assert_eq!(WrappedCipherText::unwrap(data).err(), Some(UnwrapCipherTextError::InvalidWrapper));
    }

    #[test]
    fn wrap() {
        let cipher_text = WrappedCipherText::new(
            b"encr1234567890123456123456789012",
            "arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555",
            0,
        );
        assert!(cipher_text.wrap().is_ok());

        let cipher_text = WrappedCipherText::new(
            b"123456789012345123456789012",
            "arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555",
            0,
        );
        assert_eq!(cipher_text.wrap(), Err(WrapCipherTextError::DataLength));
    }

    #[test]
    fn round_trip() {
        let cipher_text = WrappedCipherText::new(
            b"encr1234567890123456123456789012",
            "arn:aws:kms:eu-west-1:0000000:key/11111111-2222-3333-4444-555555555555",
            22,
        );
        let result = cipher_text.wrap();
        assert!(result.is_ok(), "{:?}", result);
        let data = result.unwrap();
        let result = WrappedCipherText::unwrap(&data);
        assert!(result.is_ok(), "{:?}", result);
        let cipher_text = result.unwrap();
        assert_eq!(cipher_text.version, 1);
        assert_eq!(cipher_text.key_material_generation, 22);
        assert_eq!(cipher_text.key_arn, "arn:aws:kms:eu-west-1:0000000:key/11111111-2222-3333-4444-555555555555");
        assert_eq!(cipher_text.encrypted_data, b"encr1234567890123456123456789012");
    }
}
