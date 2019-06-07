use base64::{decode as b64decode, encode as b64encode};
use futures::future::Future;
use hyper::StatusCode;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json;

use rusty_kms::key_store::*;
use rusty_kms::key_store::errors::*;
use rusty_kms::authorisation::{AuthorisationProvider, Access};
use rusty_kms::requests::*;

use crate::server::data_types::*;
use crate::server::service::KMSService;
use crate::server::targets::FutureResponse;

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn encrypt(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<EncryptRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            if request.GrantTokens.is_some() {
                warn!("GrantTokens are ignored");
            }
            let data = match b64decode(&request.Plaintext) {
                Ok(plain_text) => plain_text,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Cannot read plain text",
                ),
            };
            let len = data.len();
            if len < 1 || len > 4096 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Plain text must be between 1 and 4096 in length",
                );
            }

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
            let key = match key_store.authorised_get(&authorisation, Access::Encrypt, lookup) {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
            };
            let key_arn = key.arn_string();
            let context = request.EncryptionContext.unwrap_or_default();
            let (key_material_generation, encrypted_data) = match key.encrypt(&data, &context) {
                Ok(result) => result,
                Err(EncryptError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "DisabledException",
                    "Key is disabled",
                ),
                Err(EncryptError::RawError) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Encryption error",
                ),
            };
            let cipher_text = WrappedCipherText::new(&encrypted_data, key_arn.as_str(), key_material_generation);
            let cipher_text = match cipher_text.wrap() {
                Ok(cipher_text) => cipher_text,
                Err(WrapCipherTextError::ArnLength) | Err(WrapCipherTextError::DataLength) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Cannot wrap cipher text",
                ),
            };
            let cipher_text = b64encode(&cipher_text);
            let output = EncryptResponse {
                KeyId: &key_arn,
                CiphertextBlob: &cipher_text,
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn decrypt(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<DecryptRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            if request.GrantTokens.is_some() {
                warn!("GrantTokens are ignored");
            }
            let data = match b64decode(&request.CiphertextBlob) {
                Ok(cipher_text) => cipher_text,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Cannot read cipher text",
                ),
            };
            let len = data.len();
            if len < 1 || len > 6144 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Cipher text must be between 1 and 6144 in length",
                );
            }
            let cipher_text = match WrappedCipherText::unwrap(&data) {
                Ok(cipher_text) => cipher_text,
                Err(UnwrapCipherTextError::InvalidWrapper) | Err(UnwrapCipherTextError::UnsupportedVersion) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Cipher text is invalid",
                ),
            };

            let key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            let lookup = match Lookup::try_new(cipher_text.key_arn) {
                Ok(lookup) => lookup,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Cipher text is invalid",
                ),
            };
            let key = key_store.authorised_get(&authorisation, Access::Decrypt, lookup);
            let key = match key {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key unavailable",
                ),
            };
            let key_arn = key.arn_string();
            let context = request.EncryptionContext.unwrap_or_default();
            let plain_text = match key.decrypt(cipher_text.key_material_generation, &cipher_text.encrypted_data, &context) {
                Ok(plain_text) => plain_text,
                Err(DecryptError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "DisabledException",
                    "Key is disabled",
                ),
                Err(DecryptError::KeyMaterialGeneration) | Err(DecryptError::RawError) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Cipher text is invalid",
                ),
            };
            let plain_text = b64encode(&plain_text);
            let output = DecryptResponse {
                KeyId: &key_arn,
                Plaintext: &plain_text,
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn re_encrypt(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
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
            let request: Result<ReEncryptRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            if request.GrantTokens.is_some() {
                warn!("GrantTokens are ignored");
            }

            let data = request.CiphertextBlob;
            let len = data.len();
            if len < 1 || len > 6144 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Cipher text must be between 1 and 6144 in length",
                );
            }
            let data = match b64decode(&data) {
                Ok(cipher_text) => cipher_text,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Cannot read cipher text",
                ),
            };
            let cipher_text = match WrappedCipherText::unwrap(&data) {
                Ok(cipher_text) => cipher_text,
                Err(UnwrapCipherTextError::InvalidWrapper) | Err(UnwrapCipherTextError::UnsupportedVersion) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Cipher text is invalid",
                ),
            };

            let key_store = match key_store.lock() {
                Ok(key_store) => key_store,
                Err(_) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DependencyTimeoutException",
                    "Key store lock not available",
                ),
            };
            let dest_key_id = request.DestinationKeyId;
            let lookup = match Lookup::try_new_aliases(&authorisation, dest_key_id, false) {
                Ok(lookup) => lookup,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Cipher text is invalid",
                ),
            };
            let dest_key = match key_store.authorised_get(&authorisation, Access::ReEncryptFrom, lookup) {
                Some(dest_key) => dest_key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Destination key not found",
                ),
            };
            let dest_key_arn = dest_key.arn_string();
            let source_key_arn = cipher_text.key_arn;
            let lookup = match Lookup::try_new(source_key_arn) {
                Ok(lookup) => lookup,
                Err(()) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Invalid KeyId",
                ),
            };
            let source_key = key_store.authorised_get(&authorisation, Access::ReEncryptTo, lookup);
            let source_key = match source_key {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Source key unavailable",
                ),
            };

            let context = request.SourceEncryptionContext.unwrap_or_default();
            let plain_text = match source_key.decrypt(cipher_text.key_material_generation, &cipher_text.encrypted_data, &context) {
                Ok(plain_text) => plain_text,
                Err(DecryptError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "DisabledException",
                    "Source key is disabled",
                ),
                Err(DecryptError::KeyMaterialGeneration) | Err(DecryptError::RawError) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCiphertextException",
                    "Cipher text is invalid",
                ),
            };
            let context = request.DestinationEncryptionContext.unwrap_or_default();
            let (key_material_generation, encrypted_data) = match dest_key.encrypt(&plain_text, &context) {
                Ok(result) => result,
                Err(EncryptError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "DisabledException",
                    "Destination key is disabled",
                ),
                Err(EncryptError::RawError) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Encryption error",
                ),
            };
            let cipher_text = WrappedCipherText::new(&encrypted_data, dest_key_arn.as_str(), key_material_generation);
            let cipher_text = match cipher_text.wrap() {
                Ok(cipher_text) => cipher_text,
                Err(WrapCipherTextError::ArnLength) | Err(WrapCipherTextError::DataLength) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Cannot wrap cipher text",
                ),
            };
            let cipher_text = b64encode(&cipher_text);
            let output = ReEncryptResponse {
                KeyId: &dest_key_arn,
                SourceKeyId: source_key.key_id(),
                CiphertextBlob: &cipher_text,
            };
            let output = output.to_string();
            drop(key_store);

            response.send(output)
        }))
    }

    pub fn generate_data_key(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse, include_plaintext: bool) -> FutureResponse {
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
            let request: Result<GenerateDataKeyRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            if request.GrantTokens.is_some() {
                warn!("GrantTokens are ignored");
            }
            let key_spec = request.KeySpec.map(|key_spec| match key_spec {
                "AES_256" => 32u32,
                "AES_128" => 16u32,
                _ => 0u32,
            });
            if let Some(0) = key_spec {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidKeyUsageException",
                    "Invalid KeySpec",
                );
            }
            let data_len = request.NumberOfBytes;
            if !(key_spec.is_some() ^ data_len.is_some()) {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterCombination",
                    "Only one of KeySpec or NumberOfBytes must be provided",
                );
            }
            let data_len = key_spec.or(data_len).unwrap();
            if data_len < 1 || data_len > 1024 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    "Invalid NumberOfBytes",
                );
            }

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
            let access = if include_plaintext {
                Access::GenerateDataKey
            } else {
                Access::GenerateDataKeyWithoutPlaintext
            };
            let key = match key_store.authorised_get(&authorisation, access, lookup) {
                Some(key) => key,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    "Key not found",
                ),
            };
            let key_arn = key.arn_string();
            let mut data: Vec<u8> = vec![0u8; data_len as usize];
            if SystemRandom::new().fill(&mut data).is_err() {
                error!("Unable to generate key material");
                return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Unable to generate key material",
                );
            }
            let plain_text = if include_plaintext {
                Some(b64encode(&data))
            } else {
                None
            };
            let context = request.EncryptionContext.unwrap_or_default();
            let (key_material_generation, encrypted_data) = match key.encrypt(&data, &context) {
                Ok(result) => result,
                Err(EncryptError::InvalidState) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "DisabledException",
                    "Key is disabled",
                ),
                Err(EncryptError::RawError) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Encryption error",
                ),
            };
            let cipher_text = WrappedCipherText::new(&encrypted_data, key_arn.as_str(), key_material_generation);
            let cipher_text = match cipher_text.wrap() {
                Ok(cipher_text) => cipher_text,
                Err(WrapCipherTextError::ArnLength) | Err(WrapCipherTextError::DataLength) => return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Cannot wrap cipher text",
                ),
            };
            let cipher_text = b64encode(&cipher_text);
            let output = if let Some(plain_text) = plain_text {
                GenerateDataKeyResponse {
                    KeyId: &key_arn,
                    CiphertextBlob: &cipher_text,
                    Plaintext: &plain_text,
                }.to_string()
            } else {
                GenerateDataKeyWithoutPlaintextResponse {
                    KeyId: &key_arn,
                    CiphertextBlob: &cipher_text,
                }.to_string()
            };
            drop(key_store);

            response.send(output)
        }))
    }
}
