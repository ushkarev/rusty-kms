use std::fmt::{Display, Formatter, Result as FormatResult};

use regex::Regex;

lazy_static! {
    static ref RE_PRINCIPAL_ARN: Regex = Regex::new(
        r"^arn:aws:iam:(?P<account_id>\d+):(?P<type>root|user/|role/|federated-user/|assumed-role/)(?P<name>[a-zA-Z0-9:/_-]+)?$"  // TODO: check name
    ).expect("cannot compile regex");
}

pub enum PrincipalArn {
    Root(String),
    User(String, String),
    Role(String, String),
    FederatedUser(String, String),
    AssumedRole(String, String),
}

impl PrincipalArn {
    pub fn parse(principal_arn: &str) -> Result<PrincipalArn, ()> {
        if !principal_arn.starts_with("arn:aws:iam:") {
            return Err(());
        }

        RE_PRINCIPAL_ARN.captures(principal_arn)
            .and_then(|captures: regex::Captures| {
                let account_id = captures.name("account_id").unwrap().as_str().to_owned();
                let name = captures.name("name");
                match captures.name("type").unwrap().as_str() {
                    "root" => match name {
                        None => Some(PrincipalArn::Root(account_id)),
                        Some(_) => None,
                    },
                    "user/" => name.and_then(_checked_name).map(|name| PrincipalArn::User(account_id, name)),
                    "role/" => name.and_then(_checked_name).map(|name| PrincipalArn::Role(account_id, name)),
                    "federated-user/" => name.and_then(_checked_name).map(|name| PrincipalArn::FederatedUser(account_id, name)),
                    "assumed-role/" => name.and_then(_checked_name).map(|name| PrincipalArn::AssumedRole(account_id, name)),
                    _ => unreachable!("unexpected iam principal type match"),
                }
            })
            .ok_or(())
    }

    pub fn account_id(&self) -> &str {
        match self {
            PrincipalArn::Root(account_id) => account_id,
            PrincipalArn::User(account_id, _) => account_id,
            PrincipalArn::Role(account_id, _) => account_id,
            PrincipalArn::FederatedUser(account_id, _) => account_id,
            PrincipalArn::AssumedRole(account_id, _) => account_id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            PrincipalArn::Root(_) => "root",
            PrincipalArn::User(_, name) => name,
            PrincipalArn::Role(_, name) => name,
            PrincipalArn::FederatedUser(_, name) => name,
            PrincipalArn::AssumedRole(_, name) => name,
        }
    }

    pub fn arn_string(&self) -> String {
        match self {
            PrincipalArn::Root(account_id) => format!("arn:aws:iam:{}:root", account_id),
            PrincipalArn::User(account_id, name) => format!("arn:aws:iam:{}:user/{}", account_id, name),
            PrincipalArn::Role(account_id, name) => format!("arn:aws:iam:{}:role/{}", account_id, name),
            PrincipalArn::FederatedUser(account_id, name) => format!("arn:aws:iam:{}:federated-user/{}", account_id, name),
            PrincipalArn::AssumedRole(account_id, name) => format!("arn:aws:iam:{}:assumed-role/{}", account_id, name),
        }
    }
}

fn _checked_name(name: regex::Match) -> Option<String> {
    let name = name.as_str();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

impl Display for PrincipalArn {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{}", self.arn_string())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:root").is_ok());
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:user/user-name").is_ok());
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:assumed-role/role-name/role-session-name").is_ok());

        assert!(PrincipalArn::parse("arn:aws:iam:0000000").is_err());
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:root/").is_err());
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:root/user-name").is_err());
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:user/").is_err());
        assert!(PrincipalArn::parse("arn:aws:iam:0000000:group/group-name").is_err());
        assert!(PrincipalArn::parse("arn:aws:kms:eu-west-2:0000010:key/11111111-2222-3333-4444-555555555555").is_err());
    }
}
