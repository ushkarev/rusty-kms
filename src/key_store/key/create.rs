use chrono::Utc;
use uuid::Uuid;

use crate::key_store::crypto::*;
use crate::key_store::key::{Key, KeyArn, State, Kind};

impl Key {
    pub fn new_internal<S1, S2, S3>(region: S1, account_id: S2, description: S3) -> Key where S1: Into<String>, S2: Into<String>, S3: Into<String> {
        Key {
            arn: KeyArn::new(Uuid::new_v4(), region, account_id),
            created: Utc::now(),
            state: State::Enabled,
            kind: Kind::Internal,
            description: description.into(),
            tags: Vec::new(),
            key_materials: vec![make_key_material()],
        }
    }

    pub fn new_external<S1, S2, S3>(region: S1, account_id: S2, description: S3) -> Key where S1: Into<String>, S2: Into<String>, S3: Into<String> {
        Key {
            arn: KeyArn::new(Uuid::new_v4(), region, account_id),
            created: Utc::now(),
            state: State::PendingImport,
            kind: Kind::External,
            description: description.into(),
            tags: Vec::new(),
            key_materials: Vec::new(),
        }
    }

    pub fn verify_integrity(&self) -> Result<(), ()> {
        // should be called on ser/de
        // TODO: how to force call to this?
        // TODO: make key unusable somehow or panic?
        // TODO: is this check complete and correct?
        let ok = self.key_materials.len() <= 256 && if self.is_external() {
            match self.state() {
                State::PendingImport=> self.key_materials.is_empty(),
                State::Enabled | State::Disabled => !self.key_materials.is_empty(),
                State::PendingDeletion(_) => true,
            }
        } else {
            self.state != State::PendingImport && !self.key_materials.is_empty()
        };
        if ok {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn update_key_material_if_necessary(&mut self) {
        // should be called on ser/de and periodically
        // TODO: how to force call to this?
        let now = Utc::now();
        match &self.kind {
            Kind::ExternalExpires(date) if *date <= now => {
                info!("Deleting expired external key material for {}", self);
                self.force_remove_key_material();
            },
            Kind::InternalRotates(date) if *date <= now => {
                info!("Rotating internal key material for {}", self);
                self.force_rotate_key_material();
            },
            _ => (),
        }
    }
}
