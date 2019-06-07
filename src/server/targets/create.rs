use std::convert::TryInto;

use base64::{decode as b64decode, encode as b64encode};
use futures::future::Future;
use hyper::StatusCode;
use serde_json;

use rusty_kms::misc::{datetime_to_timestamp, timestamp_to_datetime};
use rusty_kms::key_store::*;
use rusty_kms::key_store::errors::*;
use rusty_kms::authorisation::{AuthorisationProvider, Authorisation, Access};
use rusty_kms::requests::*;

use crate::server::data_types::*;
use crate::server::service::KMSService;
use crate::server::targets::FutureResponse;

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn create_key(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<CreateKeyRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            if let Some(key_usage) = request.KeyUsage {
                if key_usage != "ENCRYPT_DECRYPT" {
                    return response.send_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        "KeyUsage must be ENCRYPT_DECRYPT",
                    );
                }
            }
            let request_tags = request.Tags.unwrap_or_default();
            let tags: Vec<Tag> = request_tags.iter()
                .filter_map(|tag| Tag::try_new(tag.TagKey, tag.TagValue).ok())
                .collect();
            if tags.len() != request_tags.len() {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "TagException",
                    "Invalid Tags",
                );
            }
            let (region, account_id, description) = (
                authorisation.region(),
                authorisation.account_id(),
                request.Description.unwrap_or_default(),
            );
            let mut key = match request.Origin {
                Some("AWS_KMS") | None => Key::new_internal(region, account_id, description),
                Some("EXTERNAL") => Key::new_external(region, account_id, description),
                _ => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Invalid Origin",
                ),
            };
            for tag in tags {
                match key.add_tag(tag) {
                    Ok(()) => (),
                    Err(AddTagError::InvalidState) => unreachable!("created key is pending deletion"),
                }
            }
            if request.CustomKeyStoreId.is_some() {
                warn!("CustomKeyStoreId is ignored");
            }
            if request.BypassPolicyLockoutSafetyCheck.is_some() {
                warn!("BypassPolicyLockoutSafetyCheck is ignored");
            }
            if request.Policy.is_some() {
                warn!("Policy is ignored");
            }

            let output = CreateKeyResponse {
                KeyMetadata: (&key).into(),
            };
            let output = output.to_string();

            let mut key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            match key_store.add_key(key) {
                Ok(()) => (),
                Err(AddKeyError::DuplicateKeyId) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "KeyId duplicated",
                ),
            }
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn import_parameters(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<GetParametersForImportRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let import_mode = match request.WrappingAlgorithm {
                "RSAES_PKCS1_V1_5" => ImportMode::PKCS1,
                "RSAES_OAEP_SHA_1" => ImportMode::OAEPSHA1,
                "RSAES_OAEP_SHA_256" => return response.send_error(
                    StatusCode::NOT_IMPLEMENTED,
                    "UnsupportedOperationException",
                    "WrappingAlgorithm not yet supported",
                ),
                _ => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid WrappingAlgorithm",
                ),
            };
            if request.WrappingKeySpec != "RSA_2048" {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "WrappingKeySpec must be RSA_2048",
                );
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
            let key_arn = key.arn_string();
            let import_token = match key.make_import_token(import_mode) {
                Ok(import_token) => import_token,
                Err(MakeImportTokenError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Key is not pending import",
                ),
            };
            let expires = datetime_to_timestamp(&import_token.expiry_date);
            let import_token: Vec<u8> = match import_token.try_into() {
                Ok(import_token) => import_token,
                Err(FromImportTokenError::Encryption) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Cannot make import token",
                ),
            };
            let import_token = b64encode(&import_token);
            let public_key = match import_key_public_data() {
                Ok(public_key) => public_key,
                Err(_) => {
                    error!("Cannot get import key public data");
                    return response.send_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "KMSInternalException",
                        "Cannot get import key public data",
                    );
                },
            };
            let public_key = b64encode(&public_key);
            let output = GetParametersForImportResponse {
                KeyId: &key_arn,
                ImportToken: &import_token,
                PublicKey: &public_key,
                ParametersValidTo: expires,
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn import_key_material(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<ImportKeyMaterialRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            let expires = match request.ExpirationModel {
                Some("KEY_MATERIAL_DOES_NOT_EXPIRE") | None => None,
                Some("KEY_MATERIAL_EXPIRES") => {
                    let expires = request.ValidTo
                        .map(timestamp_to_datetime);
                    match expires {
                        Some(expires) => expires,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "Invalid ExpirationModel",
                        ),
                    }
                },
                _ => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid ExpirationModel",
                ),
            };

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
            let import_token: Result<ImportToken, IntoImportTokenError> = b64decode(request.ImportToken)
                .or(Err(IntoImportTokenError::Invalid))
                .and_then(|import_token| import_token.as_slice().try_into());
            let import_token = match import_token {
                Ok(import_token) => import_token,
                Err(IntoImportTokenError::Invalid) | Err(IntoImportTokenError::Arn) | Err(IntoImportTokenError::Mode) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidImportTokenException",
                    "Invalid ImportToken",
                ),
                Err(IntoImportTokenError::Expired) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "ExpiredImportTokenException",
                    "ImportToken expired",
                ),
            };
            let encrypted_key_material = match b64decode(&request.EncryptedKeyMaterial) {
                Ok(encrypted_key_material) => encrypted_key_material,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Cannot read EncryptedKeyMaterial",
                ),
            };
            let key_material: Result<KeyMaterial, ()> = private_decrypt(encrypted_key_material, import_token.mode)
                .and_then(|key_material| key_material.as_slice().try_into().or(Err(())));
            let key_material = match key_material {
                Ok(key_material) => key_material,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Invalid EncryptedKeyMaterial",
                ),
            };
            match key.import_key_material(key_material, expires) {
                Ok(()) => (),
                Err(ImportKeyMaterialError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Key is not pending import",
                ),
            };
            drop(key_store);

            response.send("")
        }))
    }

    pub fn delete_key_material(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<DeleteImportedKeyMaterialRequest, _> = serde_json::from_str(&body);
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
            match key.remove_key_material() {
                Ok(()) => (),
                Err(RemoveKeyMaterialError::InternalKey) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Key is internal",
                ),
                Err(RemoveKeyMaterialError::PendingDeletion) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "UnsupportedOperationException",
                    "Key is pending deletion",
                ),
            }
            drop(key_store);

            response.send("")
        }))
    }
}
