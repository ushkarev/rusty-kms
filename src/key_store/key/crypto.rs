use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::key_store::errors::*;
use crate::key_store::crypto::*;
use crate::key_store::import_token::{ImportToken, ImportMode};
use crate::key_store::key::{Key, State, Kind};

impl Key {
    pub fn decrypt(&self, key_material_generation: u8, data: &[u8], context: &HashMap<&str, &str>) -> Result<Vec<u8>, DecryptError> {
        // NB: data must end with tag and nonce
        // TODO: call update_key_material_if_necessary?
        if self.state != State::Enabled {
            return Err(DecryptError::InvalidState);
        }
        let key_material_generation = key_material_generation as usize;
        if key_material_generation >= self.key_materials.len() {
            return Err(DecryptError::KeyMaterialGeneration);
        }
        let key_material = &self.key_materials[key_material_generation];
        let mut data = data.to_vec();
        raw_decrypt(&mut data, key_material, &context)
            .map(|_| data)
            .or(Err(DecryptError::RawError))
    }

    pub fn encrypt(&self, data: &[u8], context: &HashMap<&str, &str>) -> Result<(u8, Vec<u8>), EncryptError> {
        // NB: extends data with tag and nonce
        // TODO: call update_key_material_if_necessary?
        if self.state != State::Enabled {
            return Err(EncryptError::InvalidState);
        }
        let key_material_generation = self.key_materials.len() - 1;
        let key_material = &self.key_materials[key_material_generation];
        let mut data = data.to_vec();
        raw_encrypt(&mut data, key_material, &context)
            .map(|_| (key_material_generation as u8, data))
            .or(Err(EncryptError::RawError))
    }

    pub fn make_import_token(&self, import_mode: ImportMode) -> Result<ImportToken, MakeImportTokenError> {
        if self.state == State::PendingImport {
            Ok(ImportToken::new(self.arn_string(), import_mode))
        } else {
            Err(MakeImportTokenError::InvalidState)
        }
    }

    pub fn import_key_material(&mut self, key_material: KeyMaterial, expires: Option<DateTime<Utc>>) -> Result<(), ImportKeyMaterialError> {
        if self.state != State::PendingImport {
            return Err(ImportKeyMaterialError::InvalidState);
        }
        self.key_materials = vec![key_material];
        if let Some(expires) = expires {
            self.kind = Kind::ExternalExpires(expires);
        } else {
            self.kind = Kind::External;
        }
        self.state = State::Enabled;
        Ok(())
    }
}
