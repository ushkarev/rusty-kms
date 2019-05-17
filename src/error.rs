use std::error::Error;
use std::fmt::{Display, Formatter, Result as FormatResult};

use hyper::Error as HyperError;

#[derive(Debug)]
pub enum KMSError {
    Hyper(HyperError),
}

impl Error for KMSError {}

impl Display for KMSError {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        match self {
            KMSError::Hyper(err) => write!(f, "Hyper error {}", err),
        }
    }
}

impl From<HyperError> for KMSError {
    fn from(err: HyperError) -> KMSError {
        KMSError::Hyper(err)
    }
}
