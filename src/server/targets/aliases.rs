use std::str::FromStr;

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
use crate::server::pagination::{Marker, paginate};

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn create_alias(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<CreateAliasRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let alias = request.AliasName;
            let alias_name = match AliasName::try_new(alias, false) {
                Ok(alias_name) => alias_name,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidAliasNameException",
                    "Invalid AliasName",
                ),
            };

            let key_id = request.TargetKeyId;
            let mut key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            let lookup = match Lookup::try_new(key_id) {
                Ok(lookup) => lookup,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid KeyId",
                ),
            };
            match key_store.add_alias(&authorisation, alias_name, lookup) {
                Ok(()) => (),
                Err(AddAliasError::KeyNotFound) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
                Err(AddAliasError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "KMSInvalidStateException",
                    "Key is pending deletion",
                ),
                Err(AddAliasError::AlreadyExists) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "AlreadyExistsException",
                    "Alias already exists",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }

    pub fn list_aliases(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<ListAliasesRequest, _> = serde_json::from_str(&body);
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
            let key_filter: Box<dyn Fn(&(&str, &Key)) -> bool>;
            if let Some(key_id) = request.KeyId {
                let lookup = match Lookup::try_new(key_id) {
                    Ok(lookup) => lookup,
                    Err(()) => return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        "Invalid KeyId",
                    ),
                };
                let key = match key_store.authorised_get(&authorisation, Access::Default, lookup) {
                    Some(key) => key,
                    None => return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "NotFoundException",
                        "Key not found",
                    ),
                };
                let key_id = key.key_id().to_owned();
                key_filter = Box::new(move |(_, key)| key.key_id() == &key_id);
            } else {
                key_filter = Box::new(|_| true);
            }
            let mut aliases: Vec<(String, String, String)> = key_store.authorised_aliases(&authorisation)
                .filter(key_filter)
                .map(|(alias_arn, key)| (
                    alias_arn.to_owned(),
                    AliasArn::parse(alias_arn, false).expect("alias in store cannot be parsed").name().to_owned(),
                    key.arn_string().to_owned()
                ))
                .collect();
            drop(key_store);
            // aliases.sort_by(|a1, a2| a1.0.cmp(&a2.0));
            let per_page = request.Limit.unwrap_or(1000);
            if per_page == 0 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid Limit",
                );
            }
            let next_marker = match paginate(&mut aliases, current_page, per_page) {
                Ok(next_marker) => next_marker.map(|marker| marker.to_string()),
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid Marker",
                ),
            };
            let output = ListAliasesResponse {
                Aliases: aliases.iter().map(|(alias_arn, alias_name, key_arn)| {
                    AliasObj {
                        AliasArn: alias_arn,
                        AliasName: alias_name,
                        TargetKeyId: key_arn,
                    }
                }).collect(),
                Truncated: next_marker.is_some(),
                NextMarker: next_marker.map(Into::into),
            };

            response.send(output)
        }))
    }

    pub fn delete_alias(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<DeleteAliasRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let alias = request.AliasName;
            let alias_name = match AliasName::try_new(alias, false) {
                Ok(alias_name) => alias_name,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Invalid AliasName",
                ),
            };

            let mut key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            match key_store.remove_alias(&authorisation, alias_name) {
                Ok(()) => (),
                Err(RemoveAliasError::NotFound) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Alias not found",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }

    pub fn update_alias(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<UpdateAliasRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let alias = request.AliasName;
            let alias_name = match AliasName::try_new(alias, false) {
                Ok(alias_name) => alias_name,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidAliasNameException",
                    "Invalid AliasName",
                ),
            };

            let key_id = request.TargetKeyId;
            let mut key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            let lookup = match Lookup::try_new(key_id) {
                Ok(lookup) => lookup,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid KeyId",
                ),
            };
            match key_store.update_alias(&authorisation, alias_name, lookup) {
                Ok(()) => (),
                Err(UpdateAliasError::KeyNotFound) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
                Err(UpdateAliasError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "KMSInvalidStateException",
                    "Key is pending deletion",
                ),
                Err(UpdateAliasError::AliasNotFound) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "AliasName not found",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }
}
