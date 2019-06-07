use crate::key_store::Key;
use crate::requests::KMSRequest;

pub mod iam;

#[cfg(any(not(feature = "authorisation"), test))]
pub mod open;

#[cfg(feature = "authorisation")]
pub mod headerv4;
#[cfg(feature = "authorisation")]
pub mod access_tokens;

pub trait AuthorisationProvider where Self::Authorisation: Authorisation {
    type Authorisation;

    fn authorise(&self, request: &mut KMSRequest<Self::Authorisation>) -> Result<(), AuthorisationError>;
}

// TODO: would some sort of Into trait be better than static lifetime?
pub trait Authorisation: Send + 'static {
    fn region(&self) -> &str;
    fn account_id(&self) -> &str;

    fn authorise_body(&self, body: &str) -> Result<(), AuthorisationError>;

    fn authorises_access(&self, key: &Key, access: Access) -> Result<(), AuthorisationError>;
}

define_error!(AuthorisationError; Invalid="AccessDeniedException", InvalidSignature="IncompleteSignature", Unauthorised="AccessDeniedException");

// TODO: an enum is needed to define type of access for grants/policies
#[derive(Debug, PartialEq, Eq)]
pub enum Access {
    Default,  // for creating, modifying, deleting, tagging, aliasing, listing keys
    DescribeKey,
    Decrypt,
    Encrypt,
    GenerateDataKey,
    GenerateDataKeyWithoutPlaintext,
    ReEncryptFrom,
    ReEncryptTo,
    CreateGrant,
    RetireGrant,
}
