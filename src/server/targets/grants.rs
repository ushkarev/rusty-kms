use futures::future::Future;
use hyper::StatusCode;
use serde_json;

use rusty_kms::key_store::*;
use rusty_kms::key_store::errors::*;
use rusty_kms::authorisation::{AuthorisationProvider, Access};
use rusty_kms::requests::*;

use crate::server::data_types::*;
use crate::server::service::KMSService;
use crate::server::targets::FutureResponse;

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn create_grant(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn retire_grant(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn revoke_grant(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn list_grants(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn list_retirable_grants(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }
}
