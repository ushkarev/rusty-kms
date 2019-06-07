use futures::future::Future;
use hyper::{Request, Response, Method, StatusCode, Body};
use hyper::service::Service;

use rusty_kms::authorisation::{AuthorisationProvider, AuthorisationError};
use rusty_kms::requests::*;

mod random;
mod create;
mod modify;
mod view;
mod crypto;
mod aliases;
mod tags;

use crate::server::service::KMSService;

type FutureResponse = Box<dyn Future<Item=Response<Body>, Error=KMSError> + Send>;

impl<AP> Service for KMSService<AP> where AP: AuthorisationProvider {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = KMSError;
    type Future = FutureResponse;

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut request = KMSRequest::new(request);
        let mut response = KMSResponse::new(*request.uuid());

        if request.uri().path() != "/" {
            return Box::new(
                response.send_error(
                    StatusCode::NOT_FOUND,
                    "NotFoundException",
                    "Not found",
                )
            );
        }
        if request.method() != Method::POST {
            return Box::new(
                response.send_error(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "InvalidAction",
                    "Method not allowed",
                )
            );
        }
        let content_type = request.header(hyper::header::CONTENT_TYPE).unwrap_or("");
        if !["application/x-amz-json-1.1", "application/json"].contains(&content_type) {
            return Box::new(
                response.send_error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "InvalidAction",
                    "Only JSON based content types accepted",
                )
            );
        }

        let target = request.header("X-Amz-Target");
        if target.is_none() {
            return Box::new(
                response.send_error(
                    StatusCode::BAD_REQUEST,
                    "MissingAction",
                    "Missing target",
                )
            );
        }
        let target = target.unwrap().to_owned();
        response.action_mut().replace(target.clone());

        match self.auth_provider().authorise(&mut request) {
            Ok(()) => (),
            Err(AuthorisationError::Invalid) => return Box::new(
                response.send_error(
                    StatusCode::UNAUTHORIZED,
                    "AccessDeniedException",
                    "Unauthorized",
                )
            ),
            Err(AuthorisationError::InvalidSignature) => return Box::new(
                response.send_error(
                    StatusCode::UNAUTHORIZED,
                    "IncompleteSignature",
                    "Invalid authorisation signature",
                )
            ),
            Err(AuthorisationError::Unauthorised) => return Box::new(
                response.send_error(
                    StatusCode::UNAUTHORIZED,
                    "AccessDeniedException",
                    "Unauthorized",
                )
            ),
        }

        match target.as_str() {
            "TrentService.GenerateRandom" => self.generate_random(request, response),

            "TrentService.DescribeKey" => self.describe_key(request, response),
            "TrentService.ListKeys" => self.list_keys(request, response),

            "TrentService.CreateKey" => self.create_key(request, response),
            "TrentService.GetParametersForImport" => self.import_parameters(request, response),
            "TrentService.ImportKeyMaterial" => self.import_key_material(request, response),
            "TrentService.DeleteImportedKeyMaterial" => self.delete_key_material(request, response),

            "TrentService.TagResource" => self.tag(request, response),
            "TrentService.UntagResource" => self.untag(request, response),
            "TrentService.ListResourceTags" => self.list_tags(request, response),

            "TrentService.Encrypt" => self.encrypt(request, response),
            "TrentService.Decrypt" => self.decrypt(request, response),
            "TrentService.ReEncrypt" => self.re_encrypt(request, response),

            "TrentService.GenerateDataKey" => self.generate_data_key(request, response, true),
            "TrentService.GenerateDataKeyWithoutPlaintext" => self.generate_data_key(request, response, false),

            "TrentService.CreateAlias" => self.create_alias(request, response),
            "TrentService.UpdateAlias" => self.update_alias(request, response),
            "TrentService.DeleteAlias" => self.delete_alias(request, response),
            "TrentService.ListAliases" => self.list_aliases(request, response),

            "TrentService.UpdateKeyDescription" => self.update_description(request, response),
            "TrentService.EnableKey" => self.set_enabled(request, response, true),
            "TrentService.DisableKey" => self.set_enabled(request, response, false),

            "TrentService.ScheduleKeyDeletion" => self.schedule_deletion(request, response),
            "TrentService.CancelKeyDeletion" => self.cancel_deletion(request, response),

            "TrentService.EnableKeyRotation" => self.set_rotation(request, response, true),
            "TrentService.DisableKeyRotation" => self.set_rotation(request, response, false),
            "TrentService.GetKeyRotationStatus" => self.rotation_status(request, response),

            "TrentService.CreateGrant" | "TrentService.RetireGrant" | "TrentService.RevokeGrant" |
            "TrentService.ListGrants" | "TrentService.ListRetirableGrants" |
            "TrentService.GetKeyPolicy" | "TrentService.PutKeyPolicy" | "TrentService.ListKeyPolicies" |
            "TrentService.CreateCustomKeyStore" | "TrentService.UpdateCustomKeyStore" | "TrentService.DeleteCustomKeyStore" |
            "TrentService.DescribeCustomKeyStores" |
            "TrentService.ConnectCustomKeyStore" | "TrentService.DisconnectCustomKeyStore" => Box::new(
                response.send_error(
                    StatusCode::NOT_IMPLEMENTED,
                    "UnsupportedOperationException",
                    "Target not supported",
                )
            ),

            _ => Box::new(
                response.send_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidAction",
                    "Unknown target",
                )
            ),
        }
    }
}
