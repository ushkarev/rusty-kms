use std::collections::HashMap;
use std::collections::hash_map::{Iter as HashMapIter, Values as HashMapValues};
use std::fmt::{Display, Debug, Formatter, Result as FormatResult};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, Error as IoError, ErrorKind as IoErrorKind};
use std::num::NonZeroU32;
use std::ops::Index;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, TimeZone, Utc};
use openssl::pkey::Private;
use openssl::rsa::{Rsa, Padding};
use ring::aead::{SealingKey, seal_in_place, OpeningKey, open_in_place, AES_256_GCM, Nonce, Aad};
use ring::constant_time::verify_slices_are_equal;
use ring::digest::{self, digest};
use ring::pbkdf2::derive as pbkdf2_derive;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use time::Duration as OldDuration;
use uuid::Uuid;

use super::authorisation::Authorisation;
use super::data_types::KeyMetadata;
use super::misc::datetime_to_timestamp;

const YEAR: i64 = 365;

lazy_static! {
    pub static ref SECURE_RANDOM: SystemRandom = SystemRandom::new();
    pub static ref IMPORT_KEY_PAIR: KeyPair = KeyPair::new();
}

pub struct KeyPair {
    key: Rsa<Private>,
}

impl KeyPair {
    fn new() -> KeyPair {
        KeyPair { key: Rsa::generate(2048).expect("cannot generate RSA key") }
    }

    pub fn public_data(&self) -> Result<Vec<u8>, ()> {
        self.key.public_key_to_der().map_err(|_| ())
    }

    // for making import token, encrypt with private (and anybody could decrypt)

    fn private_encrypt<T>(&self, plain_text: T) -> Result<Vec<u8>, ()> where T: AsRef<[u8]> {
        let mut cipher_text: Vec<u8> = vec![0; self.key.size() as usize];
        self.key.private_encrypt(plain_text.as_ref(), &mut cipher_text, Padding::PKCS1)
            .map_err(|e| error!("Encryption error: {}", e))
            .and_then(|len| {
                cipher_text.drain(len..);
                Ok(cipher_text)
            })
    }

    fn public_decrypt<T>(&self, cipher_text: T) -> Result<Vec<u8>, ()> where T: AsRef<[u8]> {
        let mut plain_text: Vec<u8> = vec![0; self.key.size() as usize];
        self.key.public_decrypt(cipher_text.as_ref(), &mut plain_text, Padding::PKCS1)
            .map_err(|e| error!("Decryption error: {}", e))
            .and_then(|len| {
                plain_text.drain(len..);
                Ok(plain_text)
            })
    }

    // for importing key material, encrypt with public (so anybody can encrypt)

    pub fn private_decrypt<T>(&self, cipher_text: T, import_mode: ImportMode) -> Result<Vec<u8>, ()> where T: AsRef<[u8]> {
        let mut plain_text: Vec<u8> = vec![0; self.key.size() as usize];
        self.key.private_decrypt(cipher_text.as_ref(), &mut plain_text, import_mode.padding())
            .map_err(|e| error!("Decryption error: {}", e))
            .and_then(|len| {
                plain_text.drain(len..);
                Ok(plain_text)
            })
    }
}

#[derive(Debug)]
pub enum ImportTokenError {
    InvalidState,
    InvalidToken,
    ExpiredToken,
}

#[derive(Deserialize, Serialize)]
pub struct KeyStore {
    keys: HashMap<String, Key>,  // arn => key
    aliases: HashMap<String, String>,  // alias => arn

    #[serde(skip_deserializing, skip_serializing)]
    config: Option<(PathBuf, [u8; KEY_MATERIAL_LEN])>, // config path, password/key
}

impl KeyStore {
    pub fn new_without_persistance() -> KeyStore {
        KeyStore { keys: HashMap::new(), aliases: HashMap::new(), config: None }
    }

    pub fn new_with_persistance<T>(path: T, password: String) -> Result<Self, IoError> where T: AsRef<Path> {
        let data_path = path.as_ref();
        if !data_path.is_dir() {
            return Err(IoError::new(IoErrorKind::NotFound, "data path is not a dir"));
        }

        let password = derive_simple_key(&password);
        let config_path = data_path.join("rusty-kms.dat");

        let config_file = File::open(&config_path);
        let config_file = match config_file {
            Ok(config_file) => config_file,
            Err(err) => {
                if err.kind() == IoErrorKind::NotFound {
                    info!("Key store file does not exist");
                    let mut key_store = KeyStore::new_without_persistance();
                    key_store.config = Some((config_path, password));
                    return Ok(key_store);
                }
                return Err(err);
            }
        };

        let file_size = config_file.metadata()?.len() as usize;
        let mut config_file = BufReader::new(config_file);
        let mut config_contents = Vec::with_capacity(file_size);
        config_file.read_to_end(&mut config_contents)?;
        decrypt(&mut config_contents, &password)
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "password incorrect"))?;
        let config_contents = String::from_utf8(config_contents)
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "invalid contents"))?;

        serde_json::from_str(&config_contents)
            .map_err(IoError::from)
            .map(|mut key_store: KeyStore| {
                info!("Loaded key store with {} keys", key_store.keys.len());
                key_store.cleanup();
                key_store.config = Some((config_path, password));
                key_store
            })
    }

    pub fn cleanup(&mut self) {
        // check for key material needing rotation in internal keys
        self.keys.values_mut()
            .filter(|key| key.key_material_needs_rotation())
            .inspect(|key| info!("Rotating internal key material for {}", key.arn.arn_str()))
            .for_each(Key::rotate_key_material);

        // check for expired key material in external keys
        self.keys.values_mut()
            .filter(|key| key.key_material_has_expired())
            .inspect(|key| info!("Deleting expired external key material for {}", key.arn.arn_str()))
            .for_each(Key::delete_key_material);

        // check for keys do delete
        let arns_to_delete: Vec<String> = self.keys.values()
            .filter(|&key| key.should_be_deleted())
            .map(|key| key.arn.arn_str().to_owned())
            .collect();
        if !arns_to_delete.is_empty() {
            for arn in arns_to_delete {
                info!("Deleting key {}", arn);
                self.delete_key(&arn);
            }
        }
    }

    pub fn persist(&mut self) -> Result<(), IoError> {
        self.cleanup();
        if let Some((config_path, password)) = &self.config {
            let config_file = File::create(config_path)?;
            let mut config_file = BufWriter::new(config_file);
            return serde_json::to_string(self)
                .map_err(IoError::from)
                .and_then(|config_contents| {
                    let mut config_contents = config_contents.into_bytes();
                    encrypt(&mut config_contents, &password);
                    config_file.write_all(&config_contents)?;
                    info!("Saved key store");
                    Ok(())
                });
        }
        Ok(())
    }

    pub fn save(&mut self, key: Key) -> Result<(), &'static str> {
        let result = self.keys.insert(key.arn().arn_str().to_owned(), key);
        match result {
            Some(_) => Err("duplicate key arn"),
            None => Ok(()),
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn lookup<A>(&self, key_id_or_arn: &str, authorisation: &A) -> Option<&Key> where A: Authorisation {
        let key_arn: Result<KeyArn, _> = key_id_or_arn.parse();
        let key = match key_arn {
            Ok(_) => {
                let key = self.keys.get(key_id_or_arn);
                key.and_then(|key| if authorisation.authorises_access(key).is_ok() {
                    Some(key)
                } else {
                    None
                })
            }
            Err(_) => {
                let key_arn = KeyArn::from_authorisation(key_id_or_arn, authorisation);
                self.keys.get(&key_arn.arn_str)
            }
        };
        key.filter(|&key| key.is_usable())
    }

    pub fn lookup_with_alias<A>(&self, key_id_or_arn: &str, authorisation: &A) -> Option<&Key> where A: Authorisation {
        if key_id_or_arn.starts_with("alias/") {
            return self.get_alias(key_id_or_arn, authorisation)
                .and_then(|arn| self.keys.get(arn))
                .filter(|&key| key.is_usable());
        }
        let alias_arn: Result<AliasArn, _> = key_id_or_arn.parse();
        if let Ok(alias_arn) = alias_arn {
            return self.get_alias(alias_arn.name(), authorisation)
                .and_then(|arn| self.keys.get(arn))
                .filter(|&key| key.is_usable());
        }
        self.lookup(key_id_or_arn, authorisation)
    }

    pub fn lookup_mut<A>(&mut self, key_id_or_arn: &str, authorisation: &A) -> Option<&mut Key> where A: Authorisation {
        let key_arn: Result<KeyArn, _> = key_id_or_arn.parse();
        let key = match key_arn {
            Ok(_) => {
                let key = self.keys.get_mut(key_id_or_arn);
                key.and_then(|key| if authorisation.authorises_access(key).is_ok() {
                    Some(key)
                } else {
                    None
                })
            }
            Err(_) => {
                let key_arn = KeyArn::from_authorisation(key_id_or_arn, authorisation);
                self.keys.get_mut(&key_arn.arn_str)
            }
        };
        key.filter(|key| key.is_usable())
    }

    pub fn key_iter(&self) -> HashMapValues<String, Key> {
        self.keys.values()
    }

    pub fn authorised_keys<'a, A>(&'a self, authorisation: &'a A) -> KeyIterator<'a, A> where A: Authorisation {
        KeyIterator { iter: self.keys.iter(), authorisation }
    }

    pub fn delete_key(&mut self, arn: &str) {
        self.keys.remove(arn);
        let aliases: Vec<String> = self.aliases.iter()
            .filter(|&(_, another_arn)| another_arn == arn)
            .map(|(alias, _)| alias.to_owned())
            .collect();
        for alias in aliases {
            self.aliases.remove(&alias);
        }
    }

    pub fn get_alias<A>(&self, alias: &str, authorisation: &A) -> Option<&String> where A: Authorisation {
        self.aliases.get(alias).and_then(|arn| self.lookup(arn, authorisation).and(Some(arn)))
    }

    pub fn delete_alias<A>(&mut self, alias: &str, authorisation: &A) -> Result<(), ()> where A: Authorisation {
        match self.get_alias(alias, authorisation) {
            Some(_) => {
                self.aliases.remove(alias);
                Ok(())
            },
            None => Err(()),
        }
    }

    pub fn save_alias<A>(&mut self, alias: String, key_arn: String, _authorisation: &A) where A: Authorisation {
        self.aliases.insert(alias, key_arn);
    }

    pub fn aliases_for(&self, key_arn: &str) -> Vec<String> {
        self.aliases.iter()
            .filter(|&(_, a_key_arn)| a_key_arn == key_arn)
            .map(|(alias, _)| String::from(alias.as_str()))
            .collect()
    }

    pub fn alias_iter(&self) -> HashMapIter<String, String> {
        self.aliases.iter()
    }

    pub fn authorised_aliases<'a, A>(&'a self, authorisation: &'a A) -> AliasIterator<'a, A> where A: Authorisation {
        AliasIterator { key_store: &self, iter: self.aliases.iter(), authorisation }
    }
}

// TODO: this should be private
impl Index<&str> for KeyStore {
    type Output = Key;

    fn index(&self, arn: &str) -> &Key {
        &self.keys[arn]
    }
}

pub struct KeyIterator<'a, A> where A: Authorisation {
    authorisation: &'a A,
    iter: HashMapIter<'a, String, Key>,
}

impl<'a, A> Iterator for KeyIterator<'a, A> where A: Authorisation {
    type Item = &'a Key;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            match self.iter.next() {
                Some((_, key)) => {
                    if self.authorisation.authorises_access(key).is_ok() {
                        return Some(key);
                    }
                },
                None => return None,
            }
        }
    }
}

pub struct AliasIterator<'a, A> where A: Authorisation {
    key_store: &'a KeyStore,
    authorisation: &'a A,
    iter: HashMapIter<'a, String, String>,
}

impl<'a, A> Iterator for AliasIterator<'a, A> where A: Authorisation {
    type Item = (&'a String, &'a String);

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            match self.iter.next() {
                Some((alias, arn)) => {
                    if self.key_store.lookup(arn, self.authorisation).is_some() {
                        return Some((alias, arn));
                    }
                },
                None => return None,
            }
        }
    }
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.persist().unwrap_or_else(|e| error!("{}", e));
    }
}

impl Debug for KeyStore {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "KeyStore(keys: {})", self.keys.len())
    }
}

#[derive(Deserialize, Serialize, PartialEq)]
pub enum KeyState {
    Enabled,
    Disabled,
    PendingImport,
    PendingDeletion(DateTime<Utc>),
}

impl KeyState {
    pub fn as_str(&self) -> &str {
        match self {
            KeyState::Enabled => "Enabled",
            KeyState::Disabled => "Disabled",
            KeyState::PendingImport => "PendingImport",
            KeyState::PendingDeletion(_) => "PendingDeletion",
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq)]
pub enum KeyKind {
    Internal,
    InternalRotates(DateTime<Utc>),
    External,
    ExternalExpires(DateTime<Utc>),
}

// NB: AES_256_GCM: key_len=32 tag_len=16 nonce_len=12
pub const KEY_MATERIAL_LEN: usize = 32;  // AES_256_GCM.key_len()
const TAG_LEN: usize = 16;  // AES_256_GCM.tag_len()
const NONCE_LEN: usize = 12;  // AES_256_GCM.nonce_len()
const CONTEXT_DIGEST_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;

#[derive(Deserialize, Serialize)]
pub struct Key {
    state: KeyState,
    kind: KeyKind,
    arn: KeyArn,
    created: DateTime<Utc>,
    description: String,
    tags: HashMap<String, String>,
    key_material: Vec<[u8; KEY_MATERIAL_LEN]>,
}

impl Key {
    fn make_key_material() -> [u8; KEY_MATERIAL_LEN] {
        let mut key_material = [0u8; KEY_MATERIAL_LEN];
        SECURE_RANDOM.fill(&mut key_material).expect("unable to generate key material");
        key_material
    }

    pub fn new<A>(authorisation: &A, kind: KeyKind, description: String, tags: HashMap<String, String>) -> Key where A: Authorisation {
        let key_id = Uuid::new_v4().to_string();
        let (state, key_material) = if kind == KeyKind::Internal {
            (KeyState::Enabled, vec![Key::make_key_material()])
        } else {
            (KeyState::PendingImport, Vec::new())
        };
        Key {
            state,
            kind,
            arn: KeyArn::from_authorisation(&key_id, authorisation),
            created: Utc::now(),
            description,
            tags,
            key_material,
        }
    }

    pub fn state(&self) -> &KeyState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut KeyState {
        &mut self.state
    }

    pub fn arn(&self) -> &KeyArn {
        &self.arn
    }

    pub fn account_id(&self) -> &str {
        &self.arn.account_id
    }

    pub fn region(&self) -> &str {
        &self.arn.region
    }

    pub fn key_id(&self) -> &str {
        &self.arn.key_id
    }

    pub fn kind(&self) -> &KeyKind {
        &self.kind
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn description_mut(&mut self) -> &mut String {
        &mut self.description
    }

    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }

    pub fn tags(&self) -> &HashMap<String, String> {
        &self.tags
    }

    pub fn tags_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.tags
    }

    pub fn rotates(&self) -> bool {
        if let KeyKind::InternalRotates(_) = self.kind {
            true
        } else {
            false
        }
    }

    pub fn set_rotates(&mut self, rotates: bool) -> Result<(), ()> {
        let kind = if rotates {
            KeyKind::InternalRotates(Utc::now() + OldDuration::days(YEAR))
        } else {
            KeyKind::Internal
        };
        match self.kind {
            KeyKind::Internal | KeyKind::InternalRotates(_) => {
                self.kind = kind;
                Ok(())
            },
            KeyKind::External | KeyKind::ExternalExpires(_) => Err(()),
        }
    }

    pub fn is_external(&self) -> bool {
        match self.kind {
            KeyKind::Internal | KeyKind::InternalRotates(_) => false,
            KeyKind::External | KeyKind::ExternalExpires(_) => true,
        }
    }

    pub fn make_import_token(&self, mode: ImportMode) -> Result<(Vec<u8>, DateTime<Utc>), ()> {
        match self.state {
            KeyState::PendingImport => {
                let expiry_date = Utc::now() + OldDuration::days(7);
                let structured_token = format!("{}\n{}\n{}", self.arn.arn_str(), expiry_date.timestamp(), mode.code());
                let import_token = structured_token.into_bytes();
                let import_token = IMPORT_KEY_PAIR.private_encrypt(import_token)?;
                Ok((import_token, expiry_date))
            },
            _ => Err(()),
        }
    }

    pub fn check_import_token(&self, import_token: &[u8]) -> Result<ImportMode, ImportTokenError> {
        match self.state {
            KeyState::PendingImport => {
                let structured_token = IMPORT_KEY_PAIR.public_decrypt(import_token)
                    .map_err(|_| ImportTokenError::InvalidToken)?;
                let structured_token = String::from_utf8(structured_token)
                    .map_err(|_| ImportTokenError::InvalidToken)?;
                let mut structured_token = structured_token.split('\n');

                let arn = structured_token.next()
                    .ok_or(ImportTokenError::InvalidToken)?;

                let expiry_date = structured_token.next()
                    .ok_or(ImportTokenError::InvalidToken)?;
                let expiry_date: i64 = expiry_date.parse()
                    .map_err(|_| ImportTokenError::InvalidToken)?;
                let expiry_date = Utc.timestamp_opt(expiry_date, 0).single()
                    .ok_or(ImportTokenError::InvalidToken)?;

                let import_mode = structured_token.next()
                    .ok_or(ImportTokenError::InvalidToken)?;
                let import_mode: u8 = import_mode.parse()
                    .map_err(|_| ImportTokenError::InvalidToken)?;
                let import_mode = ImportMode::from_code(import_mode)
                    .map_err(|_| ImportTokenError::InvalidToken)?;

                if arn != self.arn.arn_str() {
                    Err(ImportTokenError::InvalidToken)
                } else if expiry_date < Utc::now() {
                    Err(ImportTokenError::ExpiredToken)
                } else {
                    Ok(import_mode)
                }
            },
            _ => Err(ImportTokenError::InvalidState),
        }
    }

    pub fn has_key_material(&self) -> bool {
        !self.key_material.is_empty()
    }

    pub fn key_material(&self) -> &[[u8; KEY_MATERIAL_LEN]] {
        &self.key_material
    }

    pub fn key_material_expiry(&self) -> Option<&DateTime<Utc>> {
        match self.kind {
            KeyKind::ExternalExpires(ref expiry_date) => Some(expiry_date),
            _ => None,
        }
    }

    fn key_material_has_expired(&self) -> bool {
        if let KeyKind::ExternalExpires(datetime) = &self.kind {
            return *datetime < Utc::now();
        }
        false
    }

    /// Force deletion of external key material regardless of expiry date
    pub fn delete_key_material(&mut self) {
        if self.is_external() {
            self.key_material.clear();
            self.state = KeyState::PendingImport;
            if let KeyKind::ExternalExpires(_) = self.kind {
                self.kind = KeyKind::External;
            }
        }
    }

    fn key_material_needs_rotation(&self) -> bool {
        if let KeyKind::InternalRotates(datetime) = &self.kind {
            return *datetime < Utc::now();
        }
        false
    }

    /// Force key material rotation regardless of rotation date but only in internal keys that have a rotation date
    fn rotate_key_material(&mut self) {
        if let KeyKind::InternalRotates(_) = self.kind {
            self.key_material.push(Key::make_key_material());
            self.kind = KeyKind::InternalRotates(Utc::now() + OldDuration::days(YEAR));
        }
    }

    pub fn import_key_material(&mut self, kind: KeyKind, key_material: [u8; KEY_MATERIAL_LEN]) {
        if self.is_external() {
            self.key_material = vec![key_material];
            self.kind = kind;
        }
    }

    fn should_be_deleted(&self) -> bool {
        if let KeyState::PendingDeletion(datetime) = &self.state {
            return *datetime < Utc::now();
        }
        false
    }

    fn is_usable(&self) -> bool {
        !self.key_material_has_expired() && !self.should_be_deleted()
    }

    // cipher text shape:
    // [ encrypted structure: [u8;?] | nonce: [u8;12] | key generation: u8 | arn [u8;?] | arn length: u8 ]
    // [      data needed for encryption/decryption < | > public wrapper needed to find key              ]
    // encrypted structure shape, once decrypted:
    // [ plain text data: [u8;?] | encryption context digest [u8;32] | tag: [u8;16] ]

    pub fn encrypt_data(&self, data: &mut Vec<u8>, context: Option<HashMap<&str, &str>>) -> Result<(), ()> {
        let count = self.key_material.len();
        if count == 0 {
            return Err(());
        }
        let key_material_generation = count - 1;
        if key_material_generation > 255 {
            error!("Too many key material generations");
            return Err(());
        }
        let context_digest = encryption_context_hash(context);
        data.extend_from_slice(context_digest.as_ref());
        encrypt(data, &self.key_material[key_material_generation]);
        self.wrap_encrypted_data(data, key_material_generation as u8);
        Ok(())
    }

    pub fn decrypt_data(&self, data: &mut Vec<u8>, key_material_generation: u8, context: Option<HashMap<&str, &str>>) -> Result<(), ()> {
        let key_material = self.key_material.get(key_material_generation as usize);
        let key_material = match key_material {
            Some(key_material) => key_material,
            None => return Err(()),
        };
        decrypt(data, key_material)?;
        if data.len() < CONTEXT_DIGEST_LEN {
            return Err(());
        }
        let offset = data.len() - CONTEXT_DIGEST_LEN;
        let context_digest = encryption_context_hash(context);
        verify_slices_are_equal(&data[offset..], context_digest.as_ref())
            .map_err(|_| ())?;
        data.drain(offset..);
        Ok(())
    }

    fn wrap_encrypted_data(&self, data: &mut Vec<u8>, key_material_generation: u8) {
        let arn = self.arn().arn_str().as_bytes();
        let arn_len = arn.len();
        assert!(arn_len < 256);
        data.push(key_material_generation);
        data.extend_from_slice(arn);
        data.push(arn_len as u8);
    }

    pub fn unwrap_encrypted_data(data: &mut Vec<u8>) -> Result<(String, u8), ()> {
        let len = data.len();
        if len == 0 {
            return Err(());
        }
        let arn_len = data[len - 1];
        if len < arn_len as usize - 1 {
            return Err(());
        }
        let arn_offset = len - (arn_len as usize) - 1;
        let arn = &data[arn_offset..len - 1];
        let key_material_generation = data[arn_offset - 1];
        let result = String::from_utf8(arn.to_owned()).map_err(|_| ());
        if result.is_ok() {
            data.drain(arn_offset - 1..);
        }
        result.map(|data| (data, key_material_generation))
    }
}

impl<'a> Into<KeyMetadata<'a>> for &'a Key {
    fn into(self) -> KeyMetadata<'a> {
        KeyMetadata {
            AWSAccountId: self.account_id(),
            Arn: self.arn().arn_str(),
            CreationDate: datetime_to_timestamp(self.created()),
            DeletionDate: if let KeyState::PendingDeletion(deletion_date) = self.state() { Some(datetime_to_timestamp(deletion_date)) } else { None },
            Description: self.description(),
            Enabled: *self.state() == KeyState::Enabled,
            ExpirationModel: if self.is_external() { Some("KEY_MATERIAL_DOES_NOT_EXPIRE") } else { None },
            KeyId: self.key_id(),
            KeyManager: "CUSTOMER",
            KeyState: self.state().as_str(),
            KeyUsage: "ENCRYPT_DECRYPT",
            Origin: if self.is_external() { "EXTERNAL" } else { "AWS_KMS" },
            ValidTo: self.key_material_expiry().map(datetime_to_timestamp),
        }
    }
}

fn derive_simple_key(password: &str) -> [u8; KEY_MATERIAL_LEN] {
    // NB: SHA256_OUTPUT_LEN = AES_256_GCM.key_len()
    static SALT: &[u8; 16] = b"\xd3\xc1\xfa\xc8\x80OFw\xb5x\xd9\xe8#ng\x05";
    let mut key = [0u8; KEY_MATERIAL_LEN];
    pbkdf2_derive(&digest::SHA256, NonZeroU32::new(120_000).unwrap(), SALT, password.as_bytes(), &mut key);
    key
}

fn encrypt(data: &mut Vec<u8>, key: &[u8; KEY_MATERIAL_LEN]) {
    static TAG_SPACE: [u8; TAG_LEN] = [0u8; TAG_LEN];
    data.extend_from_slice(&TAG_SPACE);
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).expect("cannot generate nonce");
    let sealing_key = SealingKey::new(&AES_256_GCM, key).expect("cannot create sealing key");
    let aad = Aad::from(&[0u8; 0]);
    seal_in_place(&sealing_key, Nonce::assume_unique_for_key(nonce), aad, data, AES_256_GCM.tag_len()).expect("cannot encrypt data");
    data.extend_from_slice(&nonce);
}

fn decrypt(data: &mut Vec<u8>, key: &[u8; KEY_MATERIAL_LEN]) -> Result<(), ()> {
    let nonce_offset = data.len() - AES_256_GCM.nonce_len();
    let (cipher_text, nonce) = data.split_at_mut(nonce_offset);
    let nonce = Nonce::try_assume_unique_for_key(nonce).expect("cannot read nonce");
    let opening_key = OpeningKey::new(&AES_256_GCM, key).expect("cannot create opening key");
    let aad = Aad::from(&[0u8; 0]);
    let result = open_in_place(&opening_key, nonce, aad, 0, cipher_text);
    if result.is_err() {
        return Err(());
    }
    data.drain((nonce_offset - AES_256_GCM.tag_len())..);
    Ok(())
}

fn encryption_context_hash(context: Option<HashMap<&str, &str>>) -> digest::Digest {
    match context {
        Some(context) => {
            let mut keys: Vec<&str> = context.keys().cloned().collect();
            keys.sort();
            let contents = keys.iter()
                .fold(String::new(), |mut contents, &key| {
                    contents.push_str(key);
                    contents.push_str(context[key]);
                    contents
                });
            digest(&digest::SHA256, contents.as_bytes())
        },
        None => digest(&digest::SHA256, b""),
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        Display::fmt(self.arn(), f)
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        Display::fmt(self, f)
    }
}

impl Display for KeyState {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        match self {
            KeyState::Enabled => write!(f, "enabled"),
            KeyState::Disabled => write!(f, "disabled"),
            KeyState::PendingImport => write!(f, "disabled, pending import"),
            KeyState::PendingDeletion(date) => write!(f, "disabled, will be deleted {}", date),
        }
    }
}

impl Display for KeyKind {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        match self {
            KeyKind::Internal => write!(f, "internal"),
            KeyKind::InternalRotates(date) => write!(f, "internal, rotates {}", date),
            KeyKind::External => write!(f, "external"),
            KeyKind::ExternalExpires(date) => write!(f, "external, expires {}", date),
        }
    }
}

pub enum ImportMode {
    PKCS1,
    OAEPSHA1,
    // OAEPSHA256,
}

impl ImportMode {
    fn from_code(code: u8) -> Result<ImportMode, ()> {
        match code {
            0 => Ok(ImportMode::PKCS1),
            1 => Ok(ImportMode::OAEPSHA1),
            // 2 => Ok(ImportMode::OAEPSHA256),
            _ => Err(()),
        }
    }

    fn code(&self) -> u8 {
        match self {
            ImportMode::PKCS1 => 0,
            ImportMode::OAEPSHA1 => 1,
            // ImportMode::OAEPSHA256 => 2,
        }
    }

    fn padding(&self) -> Padding {
        match self {
            ImportMode::PKCS1 => Padding::PKCS1,
            ImportMode::OAEPSHA1 => Padding::PKCS1_OAEP,
            // ImportMode::OAEPSHA256 => Padding::PKCS1_OAEP, ?
        }
    }
}

pub trait Arn: FromStr {
    fn new(id: &str, region: &str, account_id: &str) -> Self;
    fn from_authorisation(id: &str, authorisation: &Authorisation) -> Self;
    fn region(&self) -> &str;
    fn account_id(&self) -> &str;
    fn arn_str(&self) -> &str;
}

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyArn {
    region: String,
    account_id: String,
    key_id: String,
    arn_str: String,
}

impl KeyArn {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Arn for KeyArn {
    fn new(key_id: &str, region: &str, account_id: &str) -> KeyArn {
        KeyArn {
            region: region.to_owned(),
            account_id: account_id.to_owned(),
            key_id: key_id.to_owned(),
            arn_str: format!(
                "arn:aws:kms:{region}:{account_id}:key/{key_id}",
                region = region,
                account_id = account_id,
                key_id = key_id,
            ),
        }
    }

    fn from_authorisation(key_id: &str, authorisation: &Authorisation) -> KeyArn {
        KeyArn::new(key_id, authorisation.region(), authorisation.account_id())
    }

    fn region(&self) -> &str {
        &self.region
    }

    fn account_id(&self) -> &str {
        &self.account_id
    }

    fn arn_str(&self) -> &str {
        &self.arn_str
    }
}

impl Display for KeyArn {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        Display::fmt(self.arn_str(), f)
    }
}

impl FromStr for KeyArn {
    type Err = &'static str;

    fn from_str(arn: &str) -> Result<Self, <Self as FromStr>::Err> {
        if !arn.starts_with("arn:aws:kms:") {
            return Err("missing arn prefix");
        }
        let parts: Vec<&str> = arn[12..].split(':').collect();
        if parts.len() != 3 {
            return Err("malformed arn");
        }
        let key_id = parts[2];
        if !key_id.starts_with("key/") {
            return Err("malformed arn");
        }
        Ok(KeyArn::new(&key_id[4..], parts[0], parts[1]))
    }
}

#[derive(Debug)]
pub struct AliasArn {
    region: String,
    account_id: String,
    name: String,
    arn_str: String,
}

impl AliasArn {
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Arn for AliasArn {
    fn new(name: &str, region: &str, account_id: &str) -> AliasArn {
        AliasArn {
            region: region.to_owned(),
            account_id: account_id.to_owned(),
            name: name.to_owned(),
            arn_str: format!(
                "arn:aws:kms:{region}:{account_id}:{name}",
                region = region,
                account_id = account_id,
                name = name,
            ),
        }
    }

    fn from_authorisation(name: &str, authorisation: &Authorisation) -> AliasArn {
        AliasArn::new(name, authorisation.region(), authorisation.account_id())
    }

    fn region(&self) -> &str {
        &self.region
    }

    fn account_id(&self) -> &str {
        &self.account_id
    }

    fn arn_str(&self) -> &str {
        &self.arn_str
    }
}

impl Display for AliasArn {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        Display::fmt(self.arn_str(), f)
    }
}

impl FromStr for AliasArn {
    type Err = &'static str;

    fn from_str(arn: &str) -> Result<Self, <Self as FromStr>::Err> {
        if !arn.starts_with("arn:aws:kms:") {
            return Err("missing arn prefix");
        }
        let parts: Vec<&str> = arn[12..].split(':').collect();
        if parts.len() != 3 {
            return Err("malformed arn");
        }
        let name = parts[2];
        if !name.starts_with("alias/") {
            return Err("malformed arn");
        }
        Ok(AliasArn::new(name, parts[0], parts[1]))
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use super::super::authorisation::open::OpenAuthorisation;

    #[test]
    fn arn() {
        const TEST_ARN: &str = "arn:aws:kms:eu-west-2:123456:key/b9680224-ebe6-11e8-b17b-28cfe918b6d9";
        let arn: KeyArn = TEST_ARN.parse().unwrap();
        assert_eq!(arn.account_id(), "123456");
        assert_eq!(arn.region(), "eu-west-2");
        assert_eq!(arn.key_id(), "b9680224-ebe6-11e8-b17b-28cfe918b6d9");
        assert_eq!(&arn.to_string(), TEST_ARN);
    }

    #[test]
    fn encdec() {
        let mut rng = rand::thread_rng();

        let authorisation = OpenAuthorisation::new("0000000", "eu-west-2");
        let key = Key::new(&authorisation, KeyKind::Internal, String::new(), HashMap::new());
        let check = |input: &[u8]| {
            let mut data = input.to_vec();
            key.encrypt_data(&mut data, None).expect("cannot encrypt");
            assert_ne!(&data, &input);
            let (arn, key_nmaterial_generation) = Key::unwrap_encrypted_data(&mut data).expect("cannot unwrap");
            assert_eq!(&arn, key.arn().arn_str());
            key.decrypt_data(&mut data, key_nmaterial_generation, None).expect("cannot decrypt");
            assert_eq!(&data, &input);
        };

        check("Lørem impsum 😀".as_bytes());

        let mut input = [0u8; 1];
        rng.fill::<[u8]>(&mut input);
        check(&input);
        let mut input = [0u8; 64];
        rng.fill::<[u8]>(&mut input);
        check(&input);
        let mut input = [0u8; 4096];
        rng.fill::<[u8]>(&mut input);
        check(&input);
    }

    #[test]
    fn keystore() {
        let mut key_store = KeyStore::new_without_persistance();
        let authorisation = OpenAuthorisation::new("0000000", "eu-west-2");
        let key = Key::new(&authorisation, KeyKind::Internal, String::new(), HashMap::new());
        let key_arn = key.arn().arn_str().to_owned();
        let key_id = key.key_id().to_owned();
        key_store.save(key).expect("cannot save key");
        let key = key_store.lookup(&key_arn, &authorisation).unwrap();
        assert_eq!(key.key_id(), &key_id);
        let key = key_store.lookup(&key_id, &authorisation).unwrap();
        assert_eq!(key.key_id(), &key_id);
    }
}
