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
    pub fn create_custom_key_store(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn update_custom_key_store(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn delete_custom_key_store(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn describe_custom_key_stores(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn connect_custom_key_store(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }

    pub fn disconnect_custom_key_store(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        unimplemented!()
    }
}
