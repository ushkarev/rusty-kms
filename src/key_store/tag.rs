use std::fmt::{Display, Formatter, Result as FormatResult};

use serde::{Deserialize, Serialize};
use regex::Regex;

lazy_static! {
    static ref RE_TAG: Regex = Regex::new(r"^[\w\d\s+=.:/_-]+$").expect("cannot compile regex");
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct Tag {
    key: String,
    value: String,
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{}={}", self.key, self.value)
    }
}

impl Tag {
    pub fn try_new<K, V>(key: K, value: V) -> Result<Tag, TagError> where K: Into<String>, V: Into<String> {
        let key = key.into();
        if key.is_empty() || key.len() > 128 {
            return Err(TagError::InvalidKeyLength);
        }
        if key.starts_with("aws:") {
            return Err(TagError::ReservedKeyPrefix);
        }
        if !RE_TAG.is_match(&key) {
            return Err(TagError::InvalidKeyCharacters);
        }
        let value = value.into();
        if value.len() > 256 {
            return Err(TagError::InvalidValueLength);
        }
        if value.starts_with("aws:") {
            return Err(TagError::ReservedValuePrefix);
        }
        if !value.is_empty() && !RE_TAG.is_match(&value) {
            return Err(TagError::InvalidValueCharacters);
        }
        Ok(Tag { key, value })
    }

    #[inline]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[inline]
    pub fn value(&self) -> &str {
        &self.value
    }
}

define_error!(TagError; InvalidKeyCharacters="invalid key characters", InvalidValueCharacters="invalid value characters", InvalidKeyLength=" invalid key length", InvalidValueLength="invalid value length", ReservedKeyPrefix="reserved key prefix", ReservedValuePrefix="reserved value prefix");


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        assert_eq!(Tag::try_new("", ""), Err(TagError::InvalidKeyLength));
        assert_eq!(Tag::try_new("tag", "00000000010000000001000000000100000000010000000001000000000100000000010000000001000000000100000000010000000001000000000100000000010000000001000000000100000000010000000001000000000100000000010000000001000000000100000000010000000001000000000100000000010000000001"), Err(TagError::InvalidValueLength));
        assert_eq!(Tag::try_new("aws:tag", "internal"), Err(TagError::ReservedKeyPrefix));
        assert_eq!(Tag::try_new("tag", "aws:internal"), Err(TagError::ReservedValuePrefix));
        assert_eq!(Tag::try_new("\\", "value"), Err(TagError::InvalidKeyCharacters));
        assert_eq!(Tag::try_new("Email", "test@example.com"), Err(TagError::InvalidValueCharacters));

        assert!(Tag::try_new("Key", "Value").is_ok());
        assert!(Tag::try_new("Name 1", "Hello Jø").is_ok());
        assert!(Tag::try_new("Empty", "").is_ok());
    }
}
