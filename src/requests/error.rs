use std::error::Error;
use std::fmt::{Display, Formatter, Result as FormatResult};
use std::io::Error as IoError;

use hyper::Error as HyperError;

#[derive(Debug)]
pub enum KMSError {
    Hyper(HyperError),
    Io(IoError),
}

impl Error for KMSError {}

impl Display for KMSError {
    fn fmt(&self, f: &mut Formatter) -> FormatResult {
        match self {
            KMSError::Hyper(err) => write!(f, "hyper error {}", err),
            KMSError::Io(err) => write!(f, "io error {}", err),
        }
    }
}

impl From<HyperError> for KMSError {
    fn from(err: HyperError) -> KMSError {
        KMSError::Hyper(err)
    }
}

impl From<IoError> for KMSError {
    fn from(err: IoError) -> KMSError {
        KMSError::Io(err)
    }
}
