use std::fmt::{Debug, Display, Formatter, Result as FormatResult};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::misc::days_from_now;
use crate::key_store::crypto::*;
use crate::key_store::tag::Tag;

mod arn;
mod create;
mod modify;
mod crypto;
mod tags;

pub use arn::KeyArn;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    #[serde(flatten)]
    arn: KeyArn,
    created: DateTime<Utc>,
    state: State,
    kind: Kind,
    description: String,
    tags: Vec<Tag>,
    #[serde(deserialize_with = "deserialise_key_materials", serialize_with = "serialise_key_materials")]
    key_materials: Vec<KeyMaterial>,
}

impl Key {
    #[inline]
    pub fn arn(&self) -> &KeyArn {
        &self.arn
    }

    #[inline]
    pub fn arn_string(&self) -> String {
        self.arn.arn_string()
    }

    #[inline]
    pub fn key_id(&self) -> &Uuid {
        &self.arn.key_id()
    }

    #[inline]
    pub fn region(&self) -> &str {
        &self.arn.region()
    }

    #[inline]
    pub fn account_id(&self) -> &str {
        &self.arn.account_id()
    }

    #[inline]
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }

    #[inline]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[inline]
    pub fn state(&self) -> &State {
        &self.state
    }

    #[inline]
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    pub fn is_enabled(&self) -> bool {
        self.state == State::Enabled
    }

    pub fn is_external(&self) -> bool {
        match self.kind {
            Kind::Internal | Kind::InternalRotates(_) => false,
            Kind::External | Kind::ExternalExpires(_) => true,
        }
    }

    pub fn rotates(&self) -> bool {
        if let Kind::InternalRotates(_) = self.kind {
            true
        } else {
            false
        }
    }

    pub fn expires(&self) -> bool {
        if let Kind::ExternalExpires(_) = self.kind {
            true
        } else {
            false
        }
    }

    pub fn pending_deletion(&self) -> bool {
        if let State::PendingDeletion(_) = self.state {
            true
        } else {
            false
        }
    }

    pub fn key_material_expiry(&self) -> Option<&DateTime<Utc>> {
        match self.kind {
            Kind::ExternalExpires(ref expires) => Some(expires),
            _ => None,
        }
    }

    pub fn deletion_date(&self) -> Option<&DateTime<Utc>> {
        match self.state {
            State::PendingDeletion(ref date) => Some(date),
            _ => None,
        }
    }

    #[inline]
    pub fn tags(&self) -> &[Tag] {
        &self.tags
    }
}

// private methods
impl Key {
    fn force_remove_key_material(&mut self) {
        // cannot be called externally as could change kind
        self.key_materials.clear();
        self.kind = Kind::External;
        self.state = State::PendingImport;
    }

    fn force_rotate_key_material(&mut self) {
        // cannot be called externally as could change kind
        if self.key_materials.len() == 256 {
            error!("{} has too many key material generations, dropping oldest 10!", &self);
            self.key_materials = (&self.key_materials[10..256]).to_vec();
        }
        self.key_materials.push(make_key_material());
        self.kind = Kind::InternalRotates(days_from_now(365));
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{}", self.arn_string())
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        Display::fmt(self, f)
    }
}

// TODO: not currently used, but is it even logical?
impl AsRef<Uuid> for Key {
    fn as_ref(&self) -> &Uuid {
        self.key_id()
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub enum State {
    Enabled,
    Disabled,
    PendingImport,
    PendingDeletion(DateTime<Utc>),
    // Unavailable,  // when custom key store disconnected
}

impl State {
    pub fn name(&self) -> &str {
        match self {
            State::Enabled => "Enabled",
            State::Disabled => "Disabled",
            State::PendingImport => "PendingImport",
            State::PendingDeletion(_) => "PendingDeletion",
            // State::Unavailable => "Unavailable",
        }
    }
}

impl Display for State {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        match self {
            State::Enabled => write!(f, "enabled"),
            State::Disabled => write!(f, "disabled"),
            State::PendingImport => write!(f, "disabled, pending import"),
            State::PendingDeletion(date) => write!(f, "disabled, will be deleted {}", date),
            // State::Unavailable => write!(f, "unavailable", date),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub enum Kind {
    Internal,
    InternalRotates(DateTime<Utc>),
    External,
    ExternalExpires(DateTime<Utc>),
}

impl Display for Kind {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        match self {
            Kind::Internal => write!(f, "internal"),
            Kind::InternalRotates(date) => write!(f, "internal, rotates {}", date),
            Kind::External => write!(f, "external"),
            Kind::ExternalExpires(date) => write!(f, "external, expires {}", date),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use test::Bencher;

    #[test]
    fn basics() {
        let mut key = Key::new_internal("eu-west-2", "0000000", "test key");
        assert!(key.verify_integrity().is_ok());
        assert!(!key.is_external());
        assert!(key.arn_string().starts_with("arn:aws:kms:eu-west-2:0000000:key/"));
        assert_eq!(key.description(), "test key");
        assert!(key.set_description("test key 2").is_ok());
        assert_eq!(key.description(), "test key 2");
        assert_eq!(format!("{}", key), key.arn_string());

        let key = Key::new_external("eu-west-2", "0000000", "test key");
        assert!(key.verify_integrity().is_ok());
        assert!(key.is_external());
    }

    #[test]
    fn state() {
        let mut key = Key::new_internal("eu-west-2", "0000000", "test key");
        assert_eq!(key.state(), &State::Enabled);
        assert!(key.disable().is_ok());
        assert_eq!(key.state(), &State::Disabled);
        assert!(key.enable_rotation().is_err());
        assert!(key.disable_rotation().is_err());
        assert!(!key.rotates());
        assert!(key.enable().is_ok());
        assert!(key.enable().is_ok());
        assert_eq!(key.state(), &State::Enabled);
        assert!(key.disable_rotation().is_ok());
        assert!(key.enable_rotation().is_ok());
        assert!(key.rotates());
        assert_eq!(key.state(), &State::Enabled);

        let mut key = Key::new_external("eu-west-2", "0000000", "test key");
        assert_eq!(key.state(), &State::PendingImport);
        assert!(key.disable().is_err());
        assert!(key.enable().is_err());
        assert_eq!(key.state(), &State::PendingImport);
        assert!(key.enable_rotation().is_err());
        assert!(key.disable_rotation().is_err());
        assert!(key.schedule_deletion(2).is_err());
        assert!(!key.pending_deletion());
        assert!(key.schedule_deletion(8).is_ok());
        assert!(key.pending_deletion());
        assert!(key.schedule_deletion(8).is_err());
        assert!(key.cancel_deletion().is_ok());
        assert!(!key.pending_deletion());
        assert!(key.cancel_deletion().is_err());
        assert!(key.import_key_material(make_key_material(), None).is_ok());
        assert_eq!(key.state(), &State::Enabled);
        assert_eq!(key.kind(), &Kind::External);
        assert!(!key.expires());
        assert!(key.import_key_material(make_key_material(), None).is_err());
        assert!(key.remove_key_material().is_ok());
        assert_eq!(key.state(), &State::PendingImport);
        let expires = days_from_now(2);
        assert!(key.import_key_material(make_key_material(), Some(expires.clone())).is_ok());
        assert_eq!(key.state(), &State::Enabled);
        assert_eq!(key.key_material_expiry(), Some(&expires));
        assert!(key.expires());
    }

    #[test]
    fn round_trip() {
        let plain_text = b"Plain text data";
        let key = Key::new_internal("eu-west-2", "0000000", "test key");
        let result = key.encrypt(plain_text, &HashMap::new());
        assert!(result.is_ok(), "{:?}", result);
        let (key_material_generation, encrypted_data) = result.unwrap();
        assert_eq!(key_material_generation, 0u8);
        assert_ne!(&encrypted_data, plain_text);
        assert!(key.decrypt(1, &encrypted_data, &HashMap::new()).is_err());
        assert!(key.decrypt(0, plain_text, &HashMap::new()).is_err());
        let result = key.decrypt(0, &encrypted_data, &HashMap::new());
        assert!(result.is_ok(), "{:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(&decrypted_data, plain_text);
        assert!(key.decrypt(0, &encrypted_data, &HashMap::new()).is_ok());
    }

    #[test]
    fn tags() {
        let mut key = Key::new_internal("eu-west-2", "0000000", "test key");
        assert!(key.tags().is_empty());
        let tag = Tag::try_new("Name", "Test").unwrap();
        assert!(key.add_tag(tag).is_ok());
        let tag = Tag::try_new("Env", "1").unwrap();
        assert!(key.add_tag(tag).is_ok());
        assert_eq!(key.tags().len(), 2);
        let tag = Tag::try_new("Name", "Replacement").unwrap();
        assert!(key.add_tag(tag).is_ok());
        let tag = Tag::try_new("_", "").unwrap();
        assert!(key.add_tag(tag).is_ok());
        let mut tags = key.tags().iter()
            .map(|tag| format!("{}={}", tag.key(), tag.value()));
        assert_eq!(tags.next(), Some(String::from("Name=Replacement")));
        assert_eq!(tags.next(), Some(String::from("Env=1")));
        assert_eq!(tags.next(), Some(String::from("_=")));
        assert_eq!(tags.next(), None);
        assert!(key.remove_tag("_").is_ok());
        assert!(key.remove_tag("_").is_err());
        assert_eq!(key.tags().len(), 2);
    }

    #[bench]
    fn round_trip_bench(b: &mut Bencher) {
        b.iter(|| {
            let context = HashMap::new();
            let plain_text = b"Plain text data";
            let key = Key::new_internal("eu-west-2", "0000000", "test key");
            let (key_material_generation, cipher_text) = key.encrypt(plain_text, &context).unwrap();
            //println!("{}", cipher_text.as_slice());
            key.decrypt(key_material_generation, &cipher_text, &context).unwrap();
        });
    }
}
