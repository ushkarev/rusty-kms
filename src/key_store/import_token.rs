use std::convert::{TryFrom, TryInto};

use chrono::{DateTime, TimeZone, Utc};
use openssl::pkey::Private;
use openssl::rsa::{Rsa, Padding};

use crate::misc::days_from_now;
use crate::key_store::errors::*;

lazy_static! {
    // public key is shared for importing key material
    // import token is encrypted with private key to ensure same key is used for key material encryption
    // anybody could decrypt but it contains nothing interesting
    static ref IMPORT_KEY: Rsa<Private> = Rsa::generate(2048).expect("cannot generate RSA key");
}

pub fn import_key_public_data() -> Result<Vec<u8>, ()> {
    IMPORT_KEY.public_key_to_der().or(Err(()))
}

// decrypts import token sent by clients
fn public_decrypt<T>(cipher_text: T) -> Result<Vec<u8>, ()> where T: AsRef<[u8]> {
    let mut plain_text: Vec<u8> = vec![0; IMPORT_KEY.size() as usize];
    IMPORT_KEY.public_decrypt(cipher_text.as_ref(), &mut plain_text, Padding::PKCS1)
        .map_err(|e| error!("Decryption error: {}", e))
        .and_then(|len| {
            plain_text.drain(len..);
            Ok(plain_text)
        })
}

// encrypts import token sent to clients
fn private_encrypt<T>(plain_text: T) -> Result<Vec<u8>, ()> where T: AsRef<[u8]> {
    let mut cipher_text: Vec<u8> = vec![0; IMPORT_KEY.size() as usize];
    IMPORT_KEY.private_encrypt(plain_text.as_ref(), &mut cipher_text, Padding::PKCS1)
        .map_err(|e| error!("Encryption error: {}", e))
        .and_then(|len| {
            cipher_text.drain(len..);
            Ok(cipher_text)
        })
}

// decrypts key material sent by clients
pub fn private_decrypt<T>(cipher_text: T, import_mode: ImportMode) -> Result<Vec<u8>, ()> where T: AsRef<[u8]> {
    let mut plain_text: Vec<u8> = vec![0; IMPORT_KEY.size() as usize];
    IMPORT_KEY.private_decrypt(cipher_text.as_ref(), &mut plain_text, import_mode.padding())
        .map_err(|e| error!("Decryption error: {}", e))
        .and_then(|len| {
            plain_text.drain(len..);
            Ok(plain_text)
        })
}

#[derive(Debug)]
pub struct ImportToken {
    pub mode: ImportMode,
    pub expiry_date: DateTime<Utc>,
    pub key_arn: String,
}

impl ImportToken {
    pub fn new<T>(key_arn: T, mode: ImportMode) -> ImportToken where T: Into<String> {
        let expiry_date = days_from_now(7);
        ImportToken {
            mode,
            expiry_date,
            key_arn: key_arn.into(),
        }
    }
}

impl TryFrom<&[u8]> for ImportToken {
    type Error = IntoImportTokenError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value = public_decrypt(value)
            .or(Err(IntoImportTokenError::Invalid))?;
        if value.len() <= 1 + 8 {
            return Err(IntoImportTokenError::Invalid);
        }
        let mode: ImportMode = value[0].try_into()
            .or(Err(IntoImportTokenError::Mode))?;
        let expiry_date = &value[1..9];
        let expiry_date: [u8; 8] = expiry_date.try_into()
            .or(Err(IntoImportTokenError::Invalid))?; // this is impossible, right?
        let expiry_date = i64::from_be_bytes(expiry_date);
        let expiry_date = Utc.timestamp_opt(expiry_date, 0)
            .single()
            .ok_or(IntoImportTokenError::Invalid)?;
        if expiry_date <= Utc::now() {
            return Err(IntoImportTokenError::Expired);
        }
        let key_arn = &value[1 + 8..];
        let key_arn = std::str::from_utf8(key_arn)
            .or(Err(IntoImportTokenError::Arn))?;
        Ok(ImportToken {
            key_arn: key_arn.into(),
            expiry_date,
            mode,
        })
    }
}

impl TryInto<Vec<u8>> for ImportToken {
    type Error = FromImportTokenError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut output = Vec::new();
        output.push(self.mode.into());
        output.extend_from_slice(&self.expiry_date.timestamp().to_be_bytes());
        output.extend_from_slice(self.key_arn.as_bytes());
        private_encrypt(output)
            .or(Err(FromImportTokenError::Encryption))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImportMode {
    PKCS1,
    OAEPSHA1,
    // OAEPSHA256,
}

impl ImportMode {
    pub fn padding(&self) -> Padding {
        match self {
            ImportMode::PKCS1 => Padding::PKCS1,
            ImportMode::OAEPSHA1 => Padding::PKCS1_OAEP,
            // ImportMode::OAEPSHA256 => Padding::PKCS1_OAEP, ???
        }
    }
}

impl TryFrom<u8> for ImportMode {
    type Error = ();

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(ImportMode::PKCS1),
            1 => Ok(ImportMode::OAEPSHA1),
            // 2 => Ok(ImportMode::OAEPSHA256),
            _ => Err(()),
        }
    }
}

impl Into<u8> for ImportMode {
    fn into(self) -> u8 {
        match self {
            ImportMode::PKCS1 => 0,
            ImportMode::OAEPSHA1 => 1,
            // ImportMode::OAEPSHA256 => 2,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let token = ImportToken::new("arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555", ImportMode::PKCS1);
        let result = token.try_into();
        assert!(result.is_ok(), "{:?}", result);
        let bytes: Vec<u8> = result.unwrap();
        let result = bytes.as_slice().try_into();
        assert!(result.is_ok(), "{:?}", result);
        let token: ImportToken = result.unwrap();
        assert_eq!(&token.key_arn, "arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555");
        assert_eq!(&token.mode, &ImportMode::PKCS1);
    }

    #[test]
    fn expiry() {
        let mut token = ImportToken::new("arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555", ImportMode::PKCS1);
        token.expiry_date = days_from_now(-1);
        let bytes: Vec<u8> = token.try_into().unwrap();
        let result: Result<ImportToken, _> = bytes.as_slice().try_into();
        assert_eq!(result.err(), Some(IntoImportTokenError::Expired));
    }
}
