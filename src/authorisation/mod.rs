use crate::request::KMSRequest;
use crate::key_store::Key;

#[cfg(any(not(feature = "authorisation"), test))]
pub mod open;

#[cfg(feature = "authorisation")]
pub mod headerv4;
#[cfg(feature = "authorisation")]
pub mod access_tokens;

#[derive(Debug)]
pub enum AuthorisationError {
    Invalid,  // AccessDeniedException
    InvalidSignature,  // IncompleteSignature
    Unauthorised,  // AccessDeniedException
}

pub trait AuthorisationProvider where Self::Authorisation: Authorisation {
    type Authorisation;

    fn authorise(&self, request: &mut KMSRequest<Self::Authorisation>) -> Result<(), AuthorisationError>;
}

// TODO: would some sort of Into trait be better than static lifetime?
pub trait Authorisation: Send + 'static {
    fn account_id(&self) -> &str;
    fn region(&self) -> &str;

    fn authorise_body(&self, body: &str) -> Result<(), AuthorisationError>;

    fn authorises_access(&self, key: &Key) -> Result<(), AuthorisationError>;  // TODO: perhaps an enum is needed to define type of access
}
