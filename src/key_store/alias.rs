use std::borrow::Cow;
use std::fmt::{Display, Formatter, Result as FormatResult};
use std::ops::Deref;

use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref RE_ALIAS_NAME: Regex = Regex::new(r"^[a-zA-Z0-9:/_-]+$").expect("cannot compile regex");
    static ref RE_ALIAS_ARN: Regex = Regex::new(
        r"^arn:aws:kms:(?P<region>[a-z]{2}(?:-[a-z]+)+-\d):(?P<account_id>\d+):(?P<alias>alias/[a-zA-Z0-9:/_-]+)$"
    ).expect("cannot compile regex");
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct AliasName(String);

impl AliasName {
    pub fn try_new<'n, N>(name: N, allow_reserved: bool) -> Result<AliasName, AliasError> where N: Into<Cow<'n, str>> {
        let name = name.into();
        if name.is_empty() || name.len() > 256 {
            return Err(AliasError::InvalidLength);
        }
        if !name.starts_with("alias/") || name.len() < 7 {
            return Err(AliasError::InvalidPrefix);
        }
        if !allow_reserved && name.starts_with("alias/aws/") {
            return Err(AliasError::ReservedPrefix);
        }
        if !RE_ALIAS_NAME.is_match(&name) {
            return Err(AliasError::InvalidCharacters);
        }
        Ok(AliasName(name.into_owned()))
    }

    pub fn into_alias<R, A>(self, region: R, account_id: A) -> AliasArn where R: Into<String>, A: Into<String> {
        AliasArn {
            name: self,
            region: region.into(),
            account_id: account_id.into(),
        }
    }
}

impl Deref for AliasName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl Display for AliasName {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{}", &self.0)
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AliasArn {
    name: AliasName,
    region: String,
    account_id: String,
}

impl Display for AliasArn {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{}", self.name())
    }
}

impl AliasArn {
    pub fn try_new<'n, N, R, A>(name: N, region: R, account_id: A, allow_reserved: bool) -> Result<AliasArn, AliasError> where N: Into<Cow<'n, str>>, R: Into<String>, A: Into<String> {
        let name = name.into();
        AliasName::try_new(name, allow_reserved)
            .map(|alias_name| alias_name.into_alias(region, account_id))
    }

    pub fn parse(alias_arn: &str, allow_reserved: bool) -> Result<AliasArn, ()> {
        RE_ALIAS_ARN.captures(alias_arn)
            .and_then(|captures: regex::Captures| {
                let alias = captures.name("alias").unwrap().as_str();
                AliasName::try_new(alias, allow_reserved)
                    .ok()
                    .map(|alias_name| AliasArn {
                        name: alias_name,
                        region: captures.name("region").unwrap().as_str().to_owned(),
                        account_id: captures.name("account_id").unwrap().as_str().to_owned(),
                    })
            })
            .ok_or(())
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
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
            "arn:aws:kms:{region}:{account_id}:{name}",
            region = self.region(),
            account_id = self.account_id(),
            name = self.name(),
        )
    }
}

define_error!(AliasError; InvalidCharacters="invalid characters", InvalidLength="invalid length", InvalidPrefix="invalid prefix", ReservedPrefix="reserved prefix");


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_name() {
        assert_eq!(AliasName::try_new("", false), Err(AliasError::InvalidLength));
        assert_eq!(AliasName::try_new("test", false), Err(AliasError::InvalidPrefix));
        assert_eq!(AliasName::try_new("alias/aws/internal", false), Err(AliasError::ReservedPrefix));
        assert_eq!(AliasName::try_new("alias/#", false), Err(AliasError::InvalidCharacters));

        assert!(AliasName::try_new("alias/abc", false).is_ok());
        assert!(AliasName::try_new("alias/Dev/Test-Sample_1", false).is_ok());
        assert!(AliasName::try_new("alias/aws/internal", true).is_ok());
    }

    #[test]
    fn alias_arn() {
        let alias_arn = AliasArn::try_new("alias/abc", "eu-west-2", "0000010", false).unwrap();
        let alias_arn = alias_arn.arn_string();
        let result = AliasArn::parse(&alias_arn, false);
        assert!(result.is_ok(), "{:?}", result);
        let alias = result.unwrap();
        assert_eq!(alias.region(), "eu-west-2");
        assert_eq!(alias.account_id(), "0000010");
        assert_eq!(alias.name(), "alias/abc");

        assert!(AliasArn::parse("", false).is_err());
        assert!(AliasArn::parse("arn:aws:kms:eu-west-2:0000000:key/11111111-2222-3333-4444-555555555555", false).is_err());
        assert!(AliasArn::parse("arn:aws:kms:us-gov-east-1:0000010:alias/aws/1", false).is_err());
        assert!(AliasArn::parse("arn:aws:kms:us-gov-east-1:0000010:alias/aws/1", true).is_ok());
    }
}
