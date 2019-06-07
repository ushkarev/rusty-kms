use std::fmt::{Display, Formatter, Result as FormatResult};

use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

lazy_static! {
    static ref RE_KEY_ARN: Regex = Regex::new(
        r"^arn:aws:kms:(?P<region>[a-z]{2}(?:-[a-z]+)+-\d):(?P<account_id>\d+):key/(?P<key_id>[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12})$"
    ).expect("cannot compile regex");
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyArn {
    key_id: Uuid,
    region: String,
    account_id: String,
}

impl KeyArn {
    pub fn new<K, R, A>(key_id: K, region: R, account_id: A) -> KeyArn where K: Into<Uuid>, R: Into<String>, A: Into<String> {
        KeyArn {
            key_id: key_id.into(),
            region: region.into(),
            account_id: account_id.into(),
        }
    }

    pub fn parse(key_arn: &str) -> Result<KeyArn, ()> {
        RE_KEY_ARN.captures(key_arn)
            .and_then(|captures: regex::Captures| {
                let key_id = captures.name("key_id").unwrap().as_str();
                Uuid::parse_str(key_id)
                    .ok()
                    .map(|key_id| KeyArn {
                        key_id,
                        region: captures.name("region").unwrap().as_str().to_owned(),
                        account_id: captures.name("account_id").unwrap().as_str().to_owned(),
                    })
            })
            .ok_or(())
    }

    #[inline]
    pub fn key_id(&self) -> &Uuid {
        &self.key_id
    }

    #[inline]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[inline]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn arn_string(&self) -> String {
        format!(
            "arn:aws:kms:{region}:{account_id}:key/{key_id}",
            region = &self.region,
            account_id = &self.account_id,
            key_id = &self.key_id,
        )
    }
}

impl Display for KeyArn {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{}", self.arn_string())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let result = KeyArn::parse("arn:aws:kms:eu-west-2:0000010:key/11111111-2222-3333-4444-555555555555");
        assert!(result.is_ok(), "{:?}", result);
        let key_arn = result.unwrap();
        assert_eq!(key_arn.key_id().to_string(), "11111111-2222-3333-4444-555555555555");
        assert_eq!(key_arn.region(), "eu-west-2");
        assert_eq!(key_arn.account_id(), "0000010");

        assert!(KeyArn::parse("arn:aws:kms:eu-west-2:0000010:key/11111111-2222-3333-4444").is_err());
        assert!(KeyArn::parse("arn:aws:kms:us-gov-east-1:0000010:alias/test").is_err());
    }
}
