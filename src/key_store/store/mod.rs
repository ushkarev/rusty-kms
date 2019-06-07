use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Iter as HashIter;
use std::fmt::{Debug, Formatter, Result as FormatResult};
use std::fs::File;
use std::io::{BufReader, BufWriter, Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::ops::{Index, IndexMut};
use std::path::{Path, PathBuf};
use std::slice::Iter;

use chrono::Utc;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::key_store::errors::*;
use crate::key_store::crypto::{KeyMaterial, raw_decrypt, raw_encrypt};
use crate::key_store::lookup::Lookup;
use crate::key_store::alias::{AliasArn, AliasName};
use crate::key_store::key::Key;

mod access;
mod modify;

pub struct Store {
    keys: Vec<Key>,

    key_ids: HashMap<Uuid, usize>,
    key_arns: HashMap<String, usize>,
    alias_arns: HashMap<String, usize>,

    persistence: Option<(PathBuf, File, KeyMaterial)>,  // config dir, lock file, store key
}

// private methods to ensure access is authorised
impl Store {
    #[inline]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    fn iter(&self) -> KeyIterator {
        KeyIterator { iter: self.keys.iter() }
    }

    fn iter_aliases(&self) -> AliasIterator {
        AliasIterator { iter: self.alias_arns.iter(), store: &self }
    }

    fn get_by_key_id(&self, key_id: &Uuid) -> Option<&Key> {
        self.key_ids.get(key_id)
            .map(|&index| &self.keys[index])
    }

    fn get_by_key_id_mut(&mut self, key_id: &Uuid) -> Option<&mut Key> {
        self.key_ids.get(key_id)
            .cloned()
            .map(move |index| &mut self.keys[index])  // TODO: why is move necessary?
    }

    fn get_by_lookup(&self, lookup: Lookup) -> Option<&Key> {
        match lookup {
            Lookup::KeyId(key_id) => self.get_by_key_id(key_id.as_ref()),
            Lookup::KeyArn(key_arn) => {
                self.key_arns.get(key_arn.as_ref())
                    .map(|&index| (&self.keys[index]).key_id())
                    .and_then(|key_id| self.get_by_key_id(key_id))
            },
            Lookup::AliasArn(alias_arn) => {
                self.alias_arns.get(alias_arn.as_ref())
                    .map(|&index| (&self.keys[index]).key_id())
                    .and_then(|key_id| self.get_by_key_id(key_id))
            },
        }
    }

    fn get_by_lookup_mut(&mut self, lookup: Lookup) -> Option<&mut Key> {
        // TODO: why is move necessary?
        match lookup {
            Lookup::KeyId(key_id) => self.get_by_key_id_mut(key_id.as_ref()),
            Lookup::KeyArn(key_arn) => {
                self.key_arns.get(key_arn.as_ref())
                    .map(|&index| (&self.keys[index]).key_id())
                    .cloned()
                    .and_then(move |key_id| self.get_by_key_id_mut(&key_id))
            },
            Lookup::AliasArn(alias_arn) => {
                self.alias_arns.get(alias_arn.as_ref())
                    .map(|&index| (&self.keys[index]).key_id())
                    .cloned()
                    .and_then(move |key_id| self.get_by_key_id_mut(&key_id))
            },
        }
    }
}

pub struct KeyIterator<'i> {
    iter: Iter<'i, Key>,
}

impl<'i> Iterator for KeyIterator<'i> {
    type Item = &'i Key;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub struct AliasIterator<'i> {
    iter: HashIter<'i, String, usize>,
    store: &'i Store,
}

impl<'i> Iterator for AliasIterator<'i> {
    type Item = (&'i str, &'i Key);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
            .map(|(alias_arn, index)| (alias_arn.as_str(), &self.store.keys[*index]))
    }
}

impl Index<&Uuid> for Store {
    type Output = Key;

    fn index(&self, key_id: &Uuid) -> &Self::Output {
        self.get_by_key_id(key_id).expect("key not in store")
    }
}

impl IndexMut<&Uuid> for Store {
    fn index_mut(&mut self, key_id: &Uuid) -> &mut Self::Output {
        self.get_by_key_id_mut(key_id).expect("key not in store")
    }
}

impl Store {
    const FILE_NAME: &'static str = "rusty-kms.dat";
    const LOCK_NAME: &'static str = ".lock";

    pub fn new() -> Store {
        Store {
            keys: Vec::new(),
            key_ids: Default::default(),
            key_arns: Default::default(),
            alias_arns: Default::default(),
            persistence: None,
        }
    }

    pub fn with_persistence<T, C>(path: T, get_store_key: C) -> Result<Store, IoError> where T: AsRef<Path>, C: FnOnce() -> Result<KeyMaterial, IoError> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(IoError::new(IoErrorKind::NotFound, "persistence path is not a dir"));
        }
        let lock_path = path.join(Store::LOCK_NAME);
        let lock_file = File::create(lock_path)?;
        lock_file.try_lock_exclusive()
            .map_err(|_| IoError::new(IoErrorKind::WouldBlock, "key store in use"))?;

        let store_key = get_store_key()?;
        let persistence = Some((path.to_path_buf(), lock_file, store_key));

        let config_path = path.join(Store::FILE_NAME);
        let config_file = match File::open(&config_path) {
            Ok(config_file) => config_file,
            Err(e) => {
                if e.kind() == IoErrorKind::NotFound {
                    info!("Key store file does not exist");
                    let mut store = Store::new();
                    store.persistence = persistence;
                    return Ok(store);
                }
                return Err(e);
            }
        };

        let config_size = config_file.metadata()?.len() as usize;
        let mut config_contents = Vec::with_capacity(config_size);
        let mut config_reader = BufReader::new(config_file);
        config_reader.read_to_end(&mut config_contents)?;
        raw_decrypt(&mut config_contents, &store_key, &HashMap::new())
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "password incorrect or invalid store"))?;
        // dbg!(std::str::from_utf8(&config_contents).unwrap());
        serde_json::from_reader(config_contents.as_slice())
            .map_err(IoError::from)
            .and_then(|portable_store: PortableStore| {
                let mut store = Store::new();
                store.persistence = persistence;
                store.add_from_portable_store(portable_store)
                    .map(|(key_count, alias_count)| {
                        info!("Loaded key store with {} keys and {} aliases", key_count, alias_count);
                        store
                    })
                    .map_err(|e| IoError::new(IoErrorKind::WouldBlock, e))
            })
    }

    pub fn persist(&mut self) -> Result<bool, IoError> {
        self.update_if_necessary();
        if let Some((path, _, store_key)) = &self.persistence {
            let config_path = path.join(Store::FILE_NAME);
            let config_file = File::create(config_path)?;
            let mut portable_store = PortableStore { keys: Vec::new(), aliases: Vec::new() };
            portable_store.aliases = self.iter_aliases()
                .map(|(alias_arn, key)| PortableAlias {
                    name: AliasArn::parse(alias_arn, false).expect("invalid alias exists").name().to_owned(),
                    key_id: key.key_id().to_owned(),
                })
                .collect();
            std::mem::swap(&mut portable_store.keys, &mut self.keys);
            let serialisation_result = serde_json::to_vec(&portable_store)
                .map_err(IoError::from);
            std::mem::swap(&mut portable_store.keys, &mut self.keys);
            let mut config_contents = serialisation_result?;
            // dbg!(std::str::from_utf8(&config_contents).unwrap());
            raw_encrypt(&mut config_contents, &store_key, &HashMap::new())
                .map_err(|_| IoError::new(IoErrorKind::InvalidData, "cannot encrypt store"))?;
            let mut config_writer = BufWriter::new(config_file);
            config_writer.write_all(&config_contents)?;
            info!("Saved key store with {} keys and {} aliases", self.keys.len(), self.alias_arns.len());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn add_from_portable_store(&mut self, portable_store: PortableStore) -> Result<(usize, usize), AddFromPortableStoreError> {
        let (key_count, alias_count) = (portable_store.keys.len(), portable_store.aliases.len());
        let key_set: HashMap<&Uuid, (usize, &str, &str)> = portable_store.keys.iter()
            .enumerate()
            .filter_map(|(index, key)| {
                if key.verify_integrity().is_ok() {
                    Some((key.key_id(), (index, key.region(), key.account_id())))
                } else {
                    None
                }
            })
            .collect();
        if key_set.len() != key_count {
            return Err(AddFromPortableStoreError::InvalidKeys);
        }
        let aliases: Vec<(String, usize)> = portable_store.aliases.iter()
            .filter_map(|portable_alias| {
                let &(index, region, account_id) = match key_set.get(&portable_alias.key_id) {
                    Some(r) => r,
                    None => return None,
                };
                let alias_name = match AliasName::try_new(&portable_alias.name, false) {
                    Ok(alias_name) => alias_name,
                    Err(_) => return None,
                };
                let alias_arn = alias_name.into_alias(region, account_id).arn_string();
                Some((alias_arn, index))
            })
            .collect();
        if aliases.len() != alias_count {
            return Err(AddFromPortableStoreError::InvalidAliases);
        }
        if portable_store.keys.iter().any(|key| self.get_by_key_id(key.key_id()).is_some()) {
            return Err(AddFromPortableStoreError::DuplicateKeyIds);
        }
        let initial_key_count = self.keys.len();
        for mut key in portable_store.keys {
            key.update_key_material_if_necessary();
            match self.add_key(key) {
                Ok(()) => (),
                Err(AddKeyError::DuplicateKeyId) => unreachable!("duplicates should not exist"),
            }
        }
        if aliases.iter().any(|(alias_arn, _)| self.alias_arns.contains_key(alias_arn)) {
            return Err(AddFromPortableStoreError::DuplicateAliases);
        }
        for (alias_arn, index) in aliases {
            self.alias_arns.insert(alias_arn, initial_key_count + index);
        }
        self.update_if_necessary();
        Ok((key_count, alias_count))
    }

    pub fn update_if_necessary(&mut self) {
        // should be called on ser/de and periodically
        // TODO: how to force call to this?
        let now = Utc::now();
        let mut indices_to_keep: HashSet<usize> = HashSet::new();
        self.keys = self.keys.drain(..)
            .enumerate()
            .filter(|(index, key)| {
                let keep = if key.verify_integrity().is_ok() {
                    key.deletion_date()
                        .map(|deletion_date| *deletion_date > now)
                        .unwrap_or(true)
                } else {
                    error!("Key {} is invalid, deleting", key);
                    false
                };
                if keep {
                    indices_to_keep.insert(*index);
                }
                keep
            })
            .map(|(_, key)| key)
            .collect();
        self.alias_arns.retain(|_, index| indices_to_keep.contains(index));
        for key in self.keys.iter_mut() {
            key.update_key_material_if_necessary();
        }
        self.key_ids = self.keys.iter()
            .enumerate()
            .map(|(index, key)| (key.key_id().to_owned(), index))
            .collect();
        self.key_arns = self.keys.iter()
            .enumerate()
            .map(|(index, key)| (key.arn_string(), index))
            .collect();
    }
}

impl Default for Store {
    fn default() -> Self {
        Store::new()
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.persist().expect("could not persist store");
    }
}

impl Debug for Store {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "Store(keys: {}, aliases: {})", self.keys.len(), self.alias_arns.len())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableStore {
    keys: Vec<Key>,
    aliases: Vec<PortableAlias>,
}

impl PortableStore {
    pub fn load_from<T>(path: T) -> Result<PortableStore, IoError> where T: AsRef<Path> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(IoError::new(IoErrorKind::NotFound, "key path is not a file"));
        }
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }
}

impl Debug for PortableStore {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "PortableStore(keys: {}, aliases: {})", self.keys.len(), self.aliases.len())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortableAlias {
    name: String,
    key_id: Uuid,
}

impl Debug for PortableAlias {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "PortableAlias({} -> {})", &self.name, &self.key_id)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::authorisation::Authorisation;
    use crate::authorisation::open::OpenAuthorisation;
    use crate::key_store::crypto::make_key_material;

    #[test]
    fn add_remove() {
        let mut store = Store::new();
        assert!(store.is_empty());
        let key = Key::new_internal("eu-west-2", "0000000", "test key");
        assert!(store.add_key(key).is_ok());
        assert_eq!(store.len(), 1);
        let key = Key::new_internal("eu-west-2", "0000000", "test key");
        let key_id = key.key_id().to_owned();
        assert!(store.add_key(key).is_ok());
        assert_eq!(store.len(), 2);
        for _ in 0..5 {
            assert!(store.add_key(Key::new_internal("eu-west-2", "0000000", "test key")).is_ok());
        }
        assert_eq!(store.len(), 7);
        assert!(store.remove_key(&key_id).is_ok());
        assert_eq!(store.len(), 6);
        assert!(store.remove_key(&key_id).is_err());
        assert!(store.remove_key(&Uuid::nil()).is_err());
        assert_eq!(store.len(), 6);
    }

    #[test]
    fn order() {
        let mut store = Store::new();

        let mut expected_arn_order: Vec<String> = Vec::with_capacity(5);
        let mut key_ids_to_delete: Vec<Uuid> = Vec::with_capacity(5);
        for i in 0..10 {
            let key = Key::new_internal("eu-west-2", "0000000", "test key");
            let key_id = key.key_id().to_owned();
            let key_arn = key.arn_string();
            assert!(store.add_key(key).is_ok());
            if i % 2 == 0 {
                key_ids_to_delete.push(key_id);
            } else {
                expected_arn_order.push(key_arn);
            }
        }
        key_ids_to_delete.iter()
            .for_each(|key_id| assert!(store.remove_key(key_id).is_ok()));

        assert_eq!(store.len(), 5);
        let arn_order: Vec<String> = store.iter()
            .map(|key| key.arn_string())
            .collect();
        assert_eq!(arn_order, expected_arn_order);
    }

    #[test]
    fn aliases() {
        let alias_name = || AliasName::try_new("alias/test", false).unwrap();
        let authorisation = OpenAuthorisation::new("eu-west-2", "0000001");
        let mut store = Store::new();
        let key = Key::new_internal("eu-west-2", "0000001", "test key");
        let key_id = key.key_id().to_owned();
        store.add_key(key).unwrap();
        assert!(store.add_alias(&authorisation, alias_name(), key_id.into()).is_ok());
        assert!(store.add_alias(&authorisation, alias_name(), key_id.into()).is_err());
        assert!(store.remove_alias(&authorisation, alias_name()).is_ok());
        assert!(store.remove_alias(&authorisation, alias_name()).is_err());
        assert!(store.add_alias(&authorisation, alias_name(), key_id.into()).is_ok());
        let key = Key::new_internal("eu-west-2", "0000001", "test key");
        let key_id = key.key_id().to_owned();
        store.add_key(key).unwrap();
        assert!(store.update_alias(&authorisation, alias_name(), key_id.into()).is_ok());
        let alias_arn = alias_name().into_alias(authorisation.region(), authorisation.account_id()).arn_string();
        let lookup = Lookup::try_new_aliases(&authorisation, &alias_arn, false).unwrap();
        assert_eq!(store.get_by_lookup(lookup).map(|key| key.key_id()), Some(&key_id));
    }

    #[test]
    fn persistence() {
        let tmp_dir = tempdir::TempDir::new("rusty-kms").expect("cannot make temp dir");
        let tmp_dir_path = tmp_dir.path().to_owned();
        let store_key = make_key_material();
        let get_store_key = || Ok(store_key.clone());

        let mut store = Store::with_persistence(&tmp_dir, get_store_key).unwrap();
        let key = Key::new_internal("eu-west-2", "0000000", "test key");
        store.add_key(key).unwrap();
        drop(store);

        let mut store = Store::with_persistence(&tmp_dir, get_store_key).unwrap();
        assert!(Store::with_persistence(&tmp_dir, get_store_key).is_err(), "store should be locked");
        let key = Key::new_internal("eu-west-2", "0000000", "test key");
        store.add_key(key).unwrap();
        assert_eq!(store.len(), 2);
        drop(store);

        assert!(Store::with_persistence(&tmp_dir, || Ok(make_key_material())).is_err(), "store should not open with wrong password");

        tmp_dir.close().unwrap_or_else(|e| {
            eprintln!("cannot delete temp dir {}: {}", tmp_dir_path.display(), e);
        });
    }

    #[test]
    fn load_keys() {
        let mut store = Store::new();
        let result = PortableStore::load_from("examples/keys.json");
        assert!(result.is_ok(), "{:?}", result);
        let portable_store = result.unwrap();
        let result = store.add_from_portable_store(portable_store);
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(store.len(), 1);
        let lookup = Lookup::try_new("11111111-2222-3333-4444-555555555555").unwrap();
        assert!(store.get_by_lookup(lookup).is_some());
        let authorisation = OpenAuthorisation::new("eu-west-2", "0000000");
        let lookup = Lookup::try_new_aliases(&authorisation, "arn:aws:kms:eu-west-2:0000000:alias/sample", false).unwrap();
        assert!(store.get_by_lookup(lookup).is_some());
    }
}
