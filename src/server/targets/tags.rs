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
    pub fn tag(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<TagResourceRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let tags: Vec<Tag> = request.Tags.iter()
                .filter_map(|tag| Tag::try_new(tag.TagKey, tag.TagValue).ok())
                .collect();
            if request.Tags.is_empty() || tags.len() != request.Tags.len() {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "TagException",
                    "Invalid Tags",
                );
            }

            let key_id = request.KeyId;
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
            let key = match key_store.authorised_get_mut(&authorisation, Access::Default, lookup) {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
            };
            for tag in tags {
                match key.add_tag(tag) {
                    Ok(()) => (),
                    Err(AddTagError::InvalidState) => return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "KMSInvalidStateException",
                        "Key is pending deletion",
                    ),
                }
            }
            drop(key_store);

            response.send("")
        }))
    }

    pub fn untag(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<UntagResourceRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let tag_keys: Vec<Tag> = request.TagKeys.iter()
                .filter_map(|&tag_key| Tag::try_new(tag_key, "").ok())
                .collect();
            if request.TagKeys.is_empty() || tag_keys.len() != request.TagKeys.len() {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "TagException",
                    "Invalid TagKeys",
                );
            }

            let key_id = request.KeyId;
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
            let key = match key_store.authorised_get_mut(&authorisation, Access::Default, lookup) {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
            };
            for tag_key in tag_keys {
                match key.remove_tag(tag_key.key()) {
                    Ok(_tag) => (),
                    Err(RemoveTagError::InvalidState) => return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "KMSInvalidStateException",
                        "Key is pending deletion",
                    ),
                    // TODO: may end in partial execution
                    // TODO: should removing a non-existant tag fail?
                    Err(RemoveTagError::NotFound) => return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "NotFoundException",
                        "Tag not found",
                    ),
                }
            }
            drop(key_store);

            response.send("")
        }))
    }

    pub fn list_tags(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<ListTagsRequest, _> = serde_json::from_str(&body);
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

            let key_id = request.KeyId;
            let key_store = match key_store.lock() {
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
            let key = match key_store.authorised_get(&authorisation, Access::Default, lookup) {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
            };
            let mut tags: Vec<TagObj> = key.tags().iter()
                .map(|tag| TagObj { TagKey: tag.key(), TagValue: tag.value() })
                .collect();
            // tags.sort_by(|t1, t2| t1.TagKey.cmp(t2.TagKey));
            let per_page = request.Limit.unwrap_or(1000);
            if per_page == 0 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid Limit",
                );
            }
            let next_marker = match paginate(&mut tags, current_page, per_page) {
                Ok(next_marker) => next_marker.map(|marker| marker.to_string()),
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid Marker",
                ),
            };
            let output = ListTagsResponse {
                Tags: tags,
                Truncated: next_marker.is_some(),
                NextMarker: next_marker.map(Into::into),
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }
}
