use std::str::FromStr;

use futures::future::Future;
use hyper::StatusCode;
use serde_json;

use rusty_kms::key_store::*;
use rusty_kms::authorisation::{AuthorisationProvider, Access};
use rusty_kms::requests::*;

use crate::server::data_types::*;
use crate::server::service::KMSService;
use crate::server::targets::FutureResponse;
use crate::server::pagination::{Marker, paginate};

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn describe_key(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = self.key_store();
        Box::new(request.body_loaded().and_then(move |authorised_request| {
            let (authorisation, body) = match authorised_request {
                KMSAuthorisedRequest::Authorised { authorisation, body } => (authorisation, body),
                KMSAuthorisedRequest::Unauthorised => return response.send_error(
                    StatusCode::UNAUTHORIZED,
                    "IncompleteSignature",
                    "Invalid authorisation signature",
                ),
            };
            let request: Result<DescribeKeyRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let key_id = request.KeyId;
            let key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            let lookup = match Lookup::try_new_aliases(&authorisation, key_id, false) {
                Ok(lookup) => lookup,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid KeyId",
                ),
            };
            let key = match key_store.authorised_get(&authorisation, Access::DescribeKey, lookup) {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
            };
            let output = DescribeKeyResponse {
                KeyMetadata: key.into(),
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn list_keys(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = self.key_store();
        Box::new(request.body_loaded().and_then(move |authorised_request| {
            let (authorisation, body) = match authorised_request {
                KMSAuthorisedRequest::Authorised { authorisation, body } => (authorisation, body),
                KMSAuthorisedRequest::Unauthorised => return response.send_error(
                    StatusCode::UNAUTHORIZED,
                    "IncompleteSignature",
                    "Invalid authorisation signature",
                ),
            };
            let request: Result<ListKeysRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let current_page = match request.Marker {
                Some(marker) => match Marker::from_str(marker) {
                    Ok(marker) => marker.page(),
                    Err(_) => return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        "Invalid marker",
                    ),
                },
                None => 0,
            };

            let key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            let mut keys: Vec<KeyID> = key_store.authorised_keys(&authorisation)
                .map(|key| KeyID { KeyArn: key.arn_string().into(), KeyId: key.key_id() })
                .collect();
            // keys.sort_by(|k1, k2| k1.KeyArn.cmp(&k2.KeyArn));
            let per_page = request.Limit.unwrap_or(1000);
            if per_page == 0 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid Limit",
                );
            }
            let next_marker = match paginate(&mut keys, current_page, per_page) {
                Ok(next_marker) => next_marker.map(|marker| marker.to_string()),
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid Marker",
                ),
            };
            let output = ListKeysResponse {
                Keys: keys,
                Truncated: next_marker.is_some(),
                NextMarker: next_marker.map(Into::into),
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }
}
