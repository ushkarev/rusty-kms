use std::sync::{Arc, Mutex};

use futures::future::{self, FutureResult};
use hyper::Body;
use hyper::service::NewService;

use rusty_kms::key_store::Store;
use rusty_kms::authorisation::AuthorisationProvider;
use rusty_kms::requests::KMSError;

pub struct KMSNewService<AP> where AP: AuthorisationProvider {
    key_store: Arc<Mutex<Store>>,
    auth_provider: Arc<AP>,
}

impl<AP> KMSNewService<AP> where AP: AuthorisationProvider {
    pub fn new(key_store: Arc<Mutex<Store>>, auth_provider: AP) -> KMSNewService<AP> {
        KMSNewService {
            key_store,
            auth_provider: Arc::new(auth_provider),
        }
    }
}

impl<AP> NewService for KMSNewService<AP> where AP: AuthorisationProvider {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = KMSError;
    type Service = KMSService<AP>;
    type Future = FutureResult<KMSService<AP>, KMSError>;
    type InitError = KMSError;

    fn new_service(&self) -> Self::Future {
        let service = KMSService::new(
            Arc::clone(&self.key_store),
            Arc::clone(&self.auth_provider),
        );
        future::ok(service)
    }
}

pub struct KMSService<AP> where AP: AuthorisationProvider {
    key_store: Arc<Mutex<Store>>,
    auth_provider: Arc<AP>,
}

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn new(key_store: Arc<Mutex<Store>>, auth_provider: Arc<AP>) -> KMSService<AP> {
        KMSService { key_store, auth_provider }
    }

    pub fn key_store(&self) -> Arc<Mutex<Store>> {
        Arc::clone(&self.key_store)
    }

    pub fn auth_provider(&self) -> &Arc<AP> {
        &self.auth_provider
    }
}
