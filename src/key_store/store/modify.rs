use uuid::Uuid;

use crate::authorisation::{Authorisation, Access};
use crate::key_store::errors::*;
use crate::key_store::lookup::Lookup;
use crate::key_store::alias::AliasName;
use crate::key_store::key::Key;
use crate::key_store::store::Store;

impl Store {
    pub fn add_key(&mut self, key: Key) -> Result<(), AddKeyError> {
        let key_id = key.key_id();
        if self.key_ids.contains_key(key_id) {
            return Err(AddKeyError::DuplicateKeyId);
        }
        let index = self.keys.len();
        self.key_ids.insert(key_id.to_owned(), index);
        self.key_arns.insert(key.arn_string(), index);
        self.keys.push(key);
        Ok(())
    }

    pub fn remove_key(&mut self, key_id: &Uuid) -> Result<Key, RemoveKeyError> {
        self.keys.iter()
            .position(|key| key.key_id() == key_id)
            .and_then(|index| {
                let key = self.keys.remove(index);
                self.key_ids.remove(key.key_id());
                self.key_arns.remove(&key.arn_string());
                self.alias_arns.retain(|_, i| *i != index);
                for i in self.key_ids.values_mut() {
                    if *i > index {
                        *i -= 1;
                    }
                }
                for i in self.key_arns.values_mut() {
                    if *i > index {
                        *i -= 1;
                    }
                }
                for i in self.alias_arns.values_mut() {
                    if *i > index {
                        *i -= 1;
                    }
                }
                Some(key)
            })
            .ok_or(RemoveKeyError::NotFound)
    }

    // TODO: must a user be authorised to use a key to point an alias to it?
    pub fn add_alias<A>(&mut self, authorisation: &A, alias_name: AliasName, lookup: Lookup) -> Result<(), AddAliasError> where A: Authorisation {
        let key = self.authorised_get(authorisation, Access::Default, lookup).
            ok_or(AddAliasError::KeyNotFound)?;
        let index = self.key_ids.get(key.key_id()).expect("key id map missing key");
        let key = &self.keys[*index];
        if key.pending_deletion() {
            return Err(AddAliasError::InvalidState);
        }
        let alias_arn = alias_name.into_alias(authorisation.region(), authorisation.account_id()).arn_string();
        if self.alias_arns.contains_key(&alias_arn) {
            return Err(AddAliasError::AlreadyExists);
        }
        self.alias_arns.insert(alias_arn, *index);
        Ok(())
    }

    // TODO: must a user be authorised to use a key to point an alias to it?
    pub fn update_alias<A>(&mut self, authorisation: &A, alias_name: AliasName, lookup: Lookup) -> Result<(), UpdateAliasError> where A: Authorisation {
        let key = self.authorised_get(authorisation, Access::Default, lookup).
            ok_or(UpdateAliasError::KeyNotFound)?;
        let index = self.key_ids.get(key.key_id()).expect("key id map missing key");
        let key = &self.keys[*index];
        if key.pending_deletion() {
            return Err(UpdateAliasError::InvalidState);
        }
        let alias_arn = alias_name.into_alias(authorisation.region(), authorisation.account_id()).arn_string();
        self.alias_arns.get_mut(&alias_arn)
            .ok_or(UpdateAliasError::AliasNotFound)
            .and_then(|i| {
                *i = *index;
                Ok(())
            })
    }

    pub fn remove_alias<A>(&mut self, authorisation: &A, alias_name: AliasName) -> Result<(), RemoveAliasError> where A: Authorisation {
        let alias_arn = alias_name.into_alias(authorisation.region(), authorisation.account_id()).arn_string();
        self.alias_arns.remove(&alias_arn)
            .ok_or(RemoveAliasError::NotFound)
            .map(|_index| ())
    }
}
