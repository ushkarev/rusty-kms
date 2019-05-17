use std::fmt::{Debug, Formatter, Result as FormatResult};
use std::fs::File;
use std::io::{BufReader, BufWriter, Error as IoError, ErrorKind as IoErrorKind};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessToken {
    account_id: String,
    access_key: String,
    secret_key: String,
}

impl AccessToken {
    #[inline]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    #[inline]
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    #[inline]
    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }
}

impl AccessToken {
    pub fn new(account_id: String, access_key: String, secret_key: String) -> AccessToken {
        AccessToken { account_id, access_key, secret_key }
    }
}

impl Debug for AccessToken {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        write!(f, "{} for {}", self.access_key, self.account_id)
    }
}

pub fn load_access_tokens_from<T>(path: T) -> Result<Vec<AccessToken>, IoError> where T: AsRef<Path> {
    let path = path.as_ref();
    if !path.is_file() {
        return Err(IoError::new(IoErrorKind::NotFound, "access token path is not a file"));
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}

pub fn persist_access_tokens_to<T>(access_tokens: &[AccessToken], path: T) -> Result<(), IoError> where T: AsRef<Path> {
    let path = path.as_ref();
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, access_tokens)?;
    Ok(())
}
