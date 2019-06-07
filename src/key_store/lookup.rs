use std::borrow::Cow;

use uuid::Uuid;

use crate::authorisation::Authorisation;
use crate::key_store::alias::{AliasArn, AliasName};
use crate::key_store::key::{Key, KeyArn};

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'l> {
    KeyId(Cow<'l, Uuid>),
    KeyArn(Cow<'l, str>),
    AliasArn(Cow<'l, str>),
}

impl<'l> Lookup<'l> {
    pub fn try_new(lookup: &str) -> Result<Lookup, ()> {
        if let Ok(key_id) = Uuid::parse_str(lookup) {
            return Ok(Lookup::KeyId(Cow::Owned(key_id)));
        }
        if KeyArn::parse(lookup).is_ok() {
            return Ok(Lookup::KeyArn(Cow::Borrowed(lookup)));
        }
        Err(())
    }

    pub fn try_new_aliases<A>(authorisation: &A, lookup: &'l str, allow_reserved: bool) -> Result<Lookup<'l>, ()> where A: Authorisation {
        let parsed_lookup = Lookup::try_new(lookup);
        if parsed_lookup.is_ok() {
            return parsed_lookup;
        }
        if AliasArn::parse(lookup, allow_reserved).is_ok() {
            return Ok(Lookup::AliasArn(Cow::Borrowed(lookup)));
        }
        let alias = AliasName::try_new(lookup, false)
            .map(|alias| alias.into_alias(authorisation.region(), authorisation.account_id()));
        if let Ok(alias) = alias {
            return Ok(Lookup::AliasArn(Cow::Owned(alias.arn_string())));
        }
        Err(())
    }
}

impl<'l> From<Uuid> for Lookup<'l> {
    fn from(key_id: Uuid) -> Self {
        Lookup::KeyId(Cow::Owned(key_id))
    }
}

impl<'l, 'r> From<&'r Key> for Lookup<'l> where 'r: 'l {
    fn from(key: &'r Key) -> Self {
        Lookup::KeyId(Cow::Borrowed(key.key_id()))
    }
}

impl<'l, 'r> From<&'r AliasArn> for Lookup<'l> where 'r: 'l {
    fn from(alias: &'r AliasArn) -> Self {
        Lookup::AliasArn(Cow::Owned(alias.arn_string()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::authorisation::open::OpenAuthorisation;

    #[test]
    fn lookup() {
        let empty = "";
        let invalid = "123";
        let key_id = "11111111-2222-3333-4444-555555555555";
        let expected_key_id = Uuid::parse_str(key_id).unwrap();
        let key_arn = "arn:aws:kms:eu-west-2:0000010:key/11111111-2222-3333-4444-555555555555";
        let alias_arn = "arn:aws:kms:us-gov-east-1:0000010:alias/test-1";
        let alias_arn_reserved = "arn:aws:kms:us-gov-east-1:0000010:alias/aws/kms1";
        let alias = "alias/test-2";

        assert!(Lookup::try_new(empty).is_err());
        assert!(Lookup::try_new(invalid).is_err());
        assert_eq!(Lookup::try_new(key_id), Ok(Lookup::KeyId(Cow::Borrowed(&expected_key_id))));
        assert_eq!(Lookup::try_new(key_arn), Ok(Lookup::KeyArn(Cow::Borrowed(&key_arn))));
        assert!(Lookup::try_new(alias_arn).is_err());
        assert!(Lookup::try_new(alias_arn_reserved).is_err());
        assert!(Lookup::try_new(alias).is_err());

        let authorisation = OpenAuthorisation::new("eu-west-1", "0000001");
        assert!(Lookup::try_new_aliases(&authorisation, empty, false).is_err());
        assert!(Lookup::try_new_aliases(&authorisation, invalid, false).is_err());
        assert_eq!(Lookup::try_new_aliases(&authorisation, key_id, false), Ok(Lookup::KeyId(Cow::Borrowed(&expected_key_id))));
        assert_eq!(Lookup::try_new_aliases(&authorisation, key_arn, false), Ok(Lookup::KeyArn(Cow::Borrowed(&key_arn))));
        assert_eq!(Lookup::try_new_aliases(&authorisation, alias_arn, false), Ok(Lookup::AliasArn(Cow::Borrowed(alias_arn))));
        assert!(Lookup::try_new_aliases(&authorisation, alias_arn_reserved, false).is_err());
        assert_eq!(Lookup::try_new_aliases(&authorisation, alias_arn_reserved, true), Ok(Lookup::AliasArn(Cow::Borrowed(alias_arn_reserved))));
        assert_eq!(Lookup::try_new_aliases(&authorisation, alias, false), Ok(Lookup::AliasArn(Cow::Borrowed("arn:aws:kms:eu-west-1:0000001:alias/test-2"))));
    }
}
