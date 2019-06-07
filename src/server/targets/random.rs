use base64::encode as b64encode;
use futures::future::Future;
use hyper::StatusCode;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json;

use rusty_kms::authorisation::AuthorisationProvider;
use rusty_kms::requests::*;

use crate::server::data_types::*;
use crate::server::service::KMSService;
use crate::server::targets::FutureResponse;

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    pub fn generate_random(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        Box::new(request.body_loaded().and_then(move |authorised_request| {
            let (_authorisation, body) = match authorised_request {
                KMSAuthorisedRequest::Authorised { authorisation, body } => (authorisation, body),
                KMSAuthorisedRequest::Unauthorised => return response.send_error(
                    StatusCode::UNAUTHORIZED,
                    "IncompleteSignature",
                    "Invalid authorisation signature",
                ),
            };
            let request: Result<GenerateRandomRequest, _> = serde_json::from_str(&body);
            let request = match request {
                Ok(request) => request,
                Err(_) => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "Unable to parse JSON request",
                ),
            };
            debug!("Request parameters: {:?}", request);
            if request.CustomKeyStoreId.is_some() {
                warn!("CustomKeyStoreId is ignored");
            }
            let len = match request.NumberOfBytes {
                Some(len) => len,
                None => return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameterException",
                    "NumberOfBytes is a required parameter",
                ),
            };
            if len < 1 || len > 1024 {
                return response.send_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "NumberOfBytes must be between 1 and 1024",
                );
            }
            let mut random: Vec<u8> = vec![0u8; len];
            if SystemRandom::new().fill(random.as_mut()).is_err() {
                error!("Unable to generate key material");
                return response.send_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Unable to generate key material",
                );
            }
            let random = b64encode(random.as_slice());
            let output = GenerateRandomResponse { Plaintext: &random };
            response.send(output)
        }))
    }
}
