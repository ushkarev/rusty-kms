use futures::future::Future;
use hyper::StatusCode;
use serde_json;

use rusty_kms::misc::datetime_to_timestamp;
use rusty_kms::key_store::*;
use rusty_kms::key_store::errors::*;
use rusty_kms::authorisation::{AuthorisationProvider, Access};
use rusty_kms::requests::*;

use crate::server::data_types::*;
use crate::server::service::KMSService;
use crate::server::targets::FutureResponse;

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn update_description(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<UpdateKeyDescriptionRequest, _> = serde_json::from_str(&body);
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
            match key.set_description(request.Description) {
                Ok(()) => (),
                Err(SetDescriptionError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "KMSInvalidStateException",
                    "Key is pending deletion",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }

    pub fn set_enabled(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse, enabled: bool) -> FutureResponse {
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
            let request: Result<EnableRequest, _> = serde_json::from_str(&body);
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
            let result = if enabled {
                key.enable()
            } else {
                key.disable()
            };
            match result {
                Ok(()) => (),
                Err(SetEnabledError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "KMSInvalidStateException",
                    "Key cannot be enabled/disabled",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }

    pub fn schedule_deletion(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<ScheduleKeyDeletionRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let days = request.PendingWindowInDays.unwrap_or(7);

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
            let expires = match key.schedule_deletion(days) {
                Ok(expires) => expires,
                Err(ScheduleDeletionError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "KMSInvalidStateException",
                    "Key is pending deletion",
                ),
                Err(ScheduleDeletionError::DeletionWindow) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "PendingWindowInDays must be between 7 and 30",
                ),
            };
            let expires = datetime_to_timestamp(expires);
            let output = ScheduleKeyDeletionResponse {
                KeyId: key.arn_string().into(),
                DeletionDate: expires,
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn cancel_deletion(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<CancelKeyDeletionRequest, _> = serde_json::from_str(&body);
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
            match key.cancel_deletion() {
                Ok(()) => (),
                Err(CancelDeletionError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "KMSInvalidStateException",
                    "Key is not scheduled for deletion",
                ),
            }
            let output = CancelKeyDeletionResponse { KeyId: key.arn_string().into() };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn rotation_status(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<GetKeyRotationStatusRequest, _> = serde_json::from_str(&body);
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
            if key.is_external() {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Key is external",
                );
            }
            let output = GetKeyRotationStatusResponse { KeyRotationEnabled: key.rotates() };
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn set_rotation(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse, rotates: bool) -> FutureResponse {
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
            let request: Result<EnableKeyRotationRequest, _> = serde_json::from_str(&body);
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
            let result = if rotates {
                key.enable_rotation()
            } else {
                key.disable_rotation()
            };
            match result {
                Ok(()) => (),
                Err(SetRotationError::Disabled) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "DisabledException",
                    "Key is disabled",
                ),
                Err(SetRotationError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Key is external",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }
}
