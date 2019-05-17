#![deny(unused_must_use)]

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{decode as b64decode, encode as b64encode};
use chrono::Utc;
use clap;
use futures::Stream;
use futures::future::{self, Future, FutureResult};
use hyper::{Server, Request, Response, Method, StatusCode, Body};
use hyper::service::{NewService, Service};
use ring::rand::SecureRandom;
use serde_json;
use time::Duration as OldDuration;

use rusty_kms::error::KMSError;
use rusty_kms::key_store::*;
use rusty_kms::authorisation::{AuthorisationProvider, AuthorisationError};
use rusty_kms::request::*;
use rusty_kms::response::*;
use rusty_kms::data_types::*;
use rusty_kms::misc::*;


#[cfg(not(feature = "authorisation"))]
use rusty_kms::authorisation::open::OpenAuthorisationProvider;

#[cfg(not(feature = "authorisation"))]
fn add_auth_args<'a, 'b>(app: clap::App<'a, 'b>) -> clap::App<'a, 'b> {
    app
        .arg(clap::Arg::with_name("account_id").long("account-id")
            .help("Default AWS account for all key interactions")
            .default_value("0000000")
            .takes_value(true))
        .arg(clap::Arg::with_name("region").long("region")
            .help("Default AWS region for all key interactions")
            .default_value("eu-west-2")
            .takes_value(true))
}

#[cfg(not(feature = "authorisation"))]
fn load_auth_provider(args: &clap::ArgMatches) -> Result<OpenAuthorisationProvider, IoError> {
    let account_id = args.value_of("account_id").unwrap().to_owned();
    let region = args.value_of("region").unwrap().to_owned();
    Ok(OpenAuthorisationProvider::new(account_id, region))
}


#[cfg(feature = "authorisation")]
use rusty_kms::authorisation::access_tokens::load_access_tokens_from;
#[cfg(feature = "authorisation")]
use rusty_kms::authorisation::headerv4::HeaderV4AuthorisationProvider;

#[cfg(feature = "authorisation")]
fn add_auth_args<'a, 'b>(app: clap::App<'a, 'b>) -> clap::App<'a, 'b> {
    app
        .arg(clap::Arg::with_name("access_tokens").long("access-tokens")
            .help("Path to access token JSON")
            .required(true)
            .takes_value(true))
}

#[cfg(feature = "authorisation")]
fn load_auth_provider(args: &clap::ArgMatches) -> Result<HeaderV4AuthorisationProvider, IoError> {
    let access_tokens = args.value_of("access_tokens").unwrap();
    let access_tokens = load_access_tokens_from(access_tokens)?;
    Ok(HeaderV4AuthorisationProvider::new(access_tokens))
}


fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("rusty_kms=info")).init();

    let app = clap::App::new("Rusty KMS").version(env!("CARGO_PKG_VERSION"))
        .arg(clap::Arg::with_name("address")
            .help("Address and port to listen on")
            .default_value("127.0.0.1:6767"))
        .arg(clap::Arg::with_name("data_path").long("data")
            .help("Key store directory")
            .takes_value(true));
    let args = add_auth_args(app).get_matches();
    let address: SocketAddr = args.value_of("address").and_then(|address| match address.parse() {
        Ok(address) => Some(address),
        _ => {
            error!("Unable to parse address");
            std::process::exit(1);
        },
    }).unwrap();
    let key_store = args.value_of("data_path")
        .and_then(|path| {
            let password = rpassword::read_password_from_tty(Some("Key store password: ")).unwrap_or_else(|e| {
                error!("Cannot read password {}", e);
                std::process::exit(1);
            });
            let path = Path::new(path);
            KeyStore::new_with_persistance(path, password)
                .map_err(|e| {
                    error!("Cannot create key store: {}", e);
                    std::process::exit(1);
                })
                .ok()
        })
        .or_else(|| Some(KeyStore::new_without_persistance()))
        .expect("Cannot create key store");
    let key_store = Arc::new(Mutex::new(key_store));
    let key_store_ref = Arc::downgrade(&key_store);

    let (tx, rx) = futures::sync::oneshot::channel::<()>();
    let shutdown_signal = Arc::new(Mutex::new(Some(tx)));

    let auth_provider = load_auth_provider(&args).unwrap_or_else(|e| {
        error!("Cannot create auth provider: {}", e);
        std::process::exit(1);
    });

    let service = KMSNewService {
        key_store: Arc::clone(&key_store),
        auth_provider: Arc::new(auth_provider),
    };

    let server = Server::bind(&address)
        .serve(service)
        .with_graceful_shutdown(rx)
        .map_err(|e| error!("Server error: {}", e));

    info!("Starting Rusty KMS {} server on {}", env!("CARGO_PKG_VERSION"), address);
    let mut runtime = tokio::runtime::Runtime::new().expect("cannot create runtime");

    // signal handler to trigger graceful server shutdown
    runtime.spawn(
        tokio_signal::ctrl_c()
            .flatten_stream()
            .map_err(|e| {
                error!("Signal handling error: {}", e);
            })
            .for_each(move |_| {
                start_shutdown(&shutdown_signal);
                Ok(())
            })
    );

    // clean up key store periodically
    runtime.spawn(
        tokio::timer::Interval::new_interval(Duration::new(60 * 10, 0))
            .map_err(|e| {
                error!("Timer error: {}", e);
            })
            .for_each(move |_| {
                key_store_ref.upgrade().map(|key_store| {
                    let mut key_store = key_store.lock().expect("cannot lock key store");
                    key_store.cleanup();
                    drop(key_store);
                }).ok_or(())
            })
    );

    runtime.block_on(server).expect("error waiting for server to complete");
}

#[inline]
fn start_shutdown(shutdown_signal: &Arc<Mutex<Option<futures::sync::oneshot::Sender<()>>>>) {
    let mut shutdown_signal = shutdown_signal.lock().expect("cannot obtain shutdown signal");
    match shutdown_signal.take() {
        Some(shutdown_signal) => {
            warn!("Shutting down");
            shutdown_signal.send(()).expect("cannot send shutdown signal");
        },
        None => error!("Shutdown signal already used"),
    }
}

type FutureResponse = Box<Future<Item=Response<Body>, Error=KMSError> + Send>;

#[derive(Debug)]
struct KMSNewService<AP> where AP: AuthorisationProvider {
    key_store: Arc<Mutex<KeyStore>>,
    auth_provider: Arc<AP>,
}

impl<AP> NewService for KMSNewService<AP> where AP: AuthorisationProvider {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = KMSError;
    type Service = KMSService<AP>;
    type Future = FutureResult<KMSService<AP>, KMSError>;
    type InitError = KMSError;

    fn new_service(&self) -> Self::Future {
        let service = KMSService {
            key_store: Arc::clone(&self.key_store),
            auth_provider: Arc::clone(&self.auth_provider),
        };
        future::ok(service)
    }
}

#[derive(Debug)]
struct KMSService<AP> where AP: AuthorisationProvider {
    key_store: Arc<Mutex<KeyStore>>,
    auth_provider: Arc<AP>,
}

impl<AP> KMSService<AP> where AP: AuthorisationProvider {
    fn generate_random(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (_authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    if SECURE_RANDOM.fill(random.as_mut()).is_err() {
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
                })
        )
    }

    fn create_key(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let tags: HashMap<String, String> = match request.Tags {
                        Some(tags) => tags.iter()
                            .map(|tag| (tag.TagKey.to_owned(), tag.TagValue.to_owned()))
                            .collect(),
                        None => HashMap::new(),
                    };
                    if tags.iter().any(|(key, value)| !is_valid_tag(key, value)) {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "TagException",
                            "Invalid Tags",
                        );
                    }
                    let kind = match request.Origin {
                        Some("AWS_KMS") | None => KeyKind::Internal,
                        Some("EXTERNAL") => KeyKind::External,
                        _ => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "UnsupportedOperationException",
                            "Invalid Origin",
                        ),
                    };
                    if let Some(key_usage) = request.KeyUsage {
                        if key_usage != "ENCRYPT_DECRYPT" {
                            return response.send_error(
                                StatusCode::BAD_REQUEST,
                                "InvalidParameterValue",
                                "KeyUsage must be ENCRYPT_DECRYPT",
                            );
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

                    let key = Key::new(
                        &authorisation,
                        kind,
                        request.Description.unwrap_or_default().to_owned(),
                        tags,
                    );
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
                    if key_store.save(key).is_err() {
                        return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "KMSInternalException",
                            "Key Arn duplicated",
                        );
                    }
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn import_parameters(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    match key.state() {
                        KeyState::PendingImport => (),
                        _ => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is not pending import",
                        ),
                    }
                    if !key.is_external() {
                        unreachable!("non-external key in pending import state!");
                    }
                    let (import_token, expiry) = match key.make_import_token(import_mode) {
                        Ok(result) => result,
                        Err(_) => return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "KMSInternalException",
                            "Cannot make import token",
                        ),
                    };
                    let import_token = b64encode(&import_token);
                    let public_key = match IMPORT_KEY_PAIR.public_data() {
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
                        KeyId: key_id,
                        ImportToken: &import_token,
                        PublicKey: &public_key,
                        ParametersValidTo: datetime_to_timestamp(&expiry),
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn import_key_material(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let kind = match request.ExpirationModel {
                        Some("KEY_MATERIAL_DOES_NOT_EXPIRE") | None => KeyKind::External,
                        Some("KEY_MATERIAL_EXPIRES") => {
                            let expiry = request.ValidTo
                                .and_then(timestamp_to_datetime)
                                .map(KeyKind::ExternalExpires);
                            match expiry {
                                Some(expiry) => expiry,
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    match key.state() {
                        KeyState::PendingImport => (),
                        _ => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is not pending import",
                        ),
                    };
                    if !key.is_external() {
                        unreachable!("non-external key in pending import state!");
                    }
                    let import_token = match b64decode(request.ImportToken) {
                        Ok(request_import_token) => request_import_token,
                        Err(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "Cannot read ImportToken",
                        ),
                    };
                    let import_mode = match key.check_import_token(&import_token) {
                        Ok(import_mode) => import_mode,
                        Err(ImportTokenError::InvalidToken) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidImportTokenException",
                            "Invalid ImportToken",
                        ),
                        Err(ImportTokenError::ExpiredToken) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "ExpiredImportTokenException",
                            "ImportToken expired",
                        ),
                        Err(ImportTokenError::InvalidState) => unreachable!(),
                    };
                    let encrypted_key_material = match b64decode(&request.EncryptedKeyMaterial) {
                        Ok(encrypted_key_material) => encrypted_key_material,
                        Err(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "Cannot read EncryptedKeyMaterial",
                        ),
                    };
                    let key_material = match IMPORT_KEY_PAIR.private_decrypt(encrypted_key_material, import_mode) {
                        Ok(key_material) => key_material,
                        Err(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidCiphertextException",
                            "Invalid EncryptedKeyMaterial",
                        ),
                    };
                    if key_material.len() != KEY_MATERIAL_LEN {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "IncorrectKeyMaterialException",
                            "Key material is not the right length",
                        );
                    }
                    let mut fixed_key_material = [0u8; KEY_MATERIAL_LEN];
                    for (source, dest) in key_material.iter().zip(fixed_key_material.iter_mut()) {
                        *dest = *source;
                    }
                    key.import_key_material(kind, fixed_key_material);
                    *key.state_mut() = KeyState::Enabled;
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn delete_key_material(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if !key.is_external() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is not external",
                        );
                    }
                    if let KeyState::PendingDeletion(_) = key.state() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        );
                    }
                    key.delete_key_material();
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn update_description(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if let KeyState::PendingDeletion(_) = key.state() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        );
                    }
                    *key.description_mut() = request.Description.to_owned();
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn describe_key(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_with_alias(key_id, &authorisation) {
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
                })
        )
    }

    fn list_keys(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                        Some(marker) => match page_from_marker(marker) {
                            Ok(page) => page,
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
                        .map(|key| KeyID { KeyArn: key.arn().arn_str(), KeyId: key.key_id() })
                        .collect();
                    let per_page = request.Limit.unwrap_or(1000);
                    let next_marker = match paginate(&mut keys, current_page, per_page) {
                        Ok(next_marker) => next_marker,
                        Err(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "Invalid Marker",
                        ),
                    };
                    let next_marker = if next_marker.is_empty() {
                        None
                    } else {
                        Some(next_marker.as_str())
                    };
                    let output = ListKeysResponse {
                        Keys: keys,
                        Truncated: next_marker.is_some(),
                        NextMarker: next_marker,
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn tag(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    if request.Tags.iter().any(|tag| !is_valid_tag(tag.TagKey, tag.TagValue)) {
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if let KeyState::PendingDeletion(_) = key.state() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        );
                    }
                    key.tags_mut().extend(request.Tags.iter().map(|tag| (tag.TagKey.to_owned(), tag.TagValue.to_owned())));
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn untag(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    if request.TagKeys.iter().any(|&key| !is_valid_tag(key, "x")) {
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if let KeyState::PendingDeletion(_) = key.state() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        );
                    }
                    let tags = key.tags_mut();
                    for tag in request.TagKeys {
                        tags.remove(tag);
                    }
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn list_tags(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                        Some(marker) => match page_from_marker(marker) {
                            Ok(page) => page,
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
                    let key = match key_store.lookup(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    let mut tags: Vec<Tag> = key.tags().iter()
                            .map(|(key, value)| Tag { TagKey: &key, TagValue: &value })
                            .collect();
                    let per_page = request.Limit.unwrap_or(1000);
                    let next_marker = match paginate(&mut tags, current_page, per_page) {
                        Ok(next_marker) => next_marker,
                        Err(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "Invalid Marker",
                        ),
                    };
                    let next_marker = if next_marker.is_empty() {
                        None
                    } else {
                        Some(next_marker.as_str())
                    };
                    let output = ListTagsResponse {
                        Tags: tags,
                        Truncated: next_marker.is_some(),
                        NextMarker: next_marker,
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn encrypt(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let mut data = match b64decode(&request.Plaintext) {
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
                    let key = match key_store.lookup_with_alias(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if *key.state() != KeyState::Enabled {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "DisabledException",
                            "Key is disabled",
                        );
                    }
                    if key.encrypt_data(&mut data, request.EncryptionContext).is_err() {
                        error!("Key material missing");
                        return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "KMSInternalException",
                            "Key material missing",
                        );
                    }
                    let cipher_text = b64encode(&data);
                    let output = EncryptResponse {
                        KeyId: key_id,
                        CiphertextBlob: &cipher_text,
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn decrypt(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let mut data = match b64decode(&request.CiphertextBlob) {
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
                    let (key_arn, key_material_generation) = match Key::unwrap_encrypted_data(&mut data) {
                        Ok(key_arn) => key_arn,
                        Err(_) => return response.send_error(
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
                    let key = key_store.lookup(&key_arn, &authorisation);
                    let key = match key {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key unavailable",
                        ),
                    };
                    if *key.state() != KeyState::Enabled {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "DisabledException",
                            "Key is disabled",
                        );
                    }
                    if key.decrypt_data(&mut data, key_material_generation, request.EncryptionContext).is_err() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidCiphertextException",
                            "Cipher text is invalid",
                        );
                    }
                    let plain_text = b64encode(&data);
                    let output = DecryptResponse {
                        KeyId: key.key_id(),
                        Plaintext: &plain_text,
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn re_encrypt(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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

                    let mut data = match b64decode(&request.CiphertextBlob) {
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
                    let (source_key_arn, key_material_generation) = match Key::unwrap_encrypted_data(&mut data) {
                        Ok(source_key_arn) => source_key_arn,
                        Err(_) => return response.send_error(
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

                    let dest_key = match key_store.lookup_with_alias(request.DestinationKeyId, &authorisation) {
                        Some(dest_key) => dest_key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Destination key not found",
                        ),
                    };
                    if *dest_key.state() != KeyState::Enabled {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "DisabledException",
                            "Destination key is disabled",
                        );
                    }

                    let source_key = key_store.lookup(&source_key_arn, &authorisation);
                    let source_key = match source_key {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Source key unavailable",
                        ),
                    };
                    if *source_key.state() != KeyState::Enabled {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "DisabledException",
                            "Source key is disabled",
                        );
                    }
                    if source_key.decrypt_data(&mut data, key_material_generation, request.SourceEncryptionContext).is_err() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidCiphertextException",
                            "Cipher text is invalid",
                        );
                    }
                    if dest_key.encrypt_data(&mut data, request.DestinationEncryptionContext).is_err() {
                        error!("Key material missing");
                        return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "KMSInternalException",
                            "Key material missing",
                        );
                    }
                    let cipher_text = b64encode(&data);

                    let output = ReEncryptResponse {
                        KeyId: dest_key.key_id(),
                        SourceKeyId: source_key.key_id(),
                        CiphertextBlob: &cipher_text,
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn generate_data_key(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse, include_plaintext: bool) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_with_alias(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if *key.state() != KeyState::Enabled {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "DisabledException",
                            "Key is disabled",
                        );
                    }
                    let mut data: Vec<u8> = vec![0u8; data_len as usize];
                    if SECURE_RANDOM.fill(data.as_mut()).is_err() {
                        error!("Unable to generate key material");
                        return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "KMSInternalException",
                            "Unable to generate key material",
                        );
                    }
                    let output = if include_plaintext {
                        let mut data_copy = Vec::with_capacity(data.len());
                        data_copy.extend_from_slice(&data);
                        if key.encrypt_data(&mut data, request.EncryptionContext).is_err() {
                            error!("Key material missing");
                            return response.send_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "KMSInternalException",
                                "Key material missing",
                            );
                        }
                        let cipher_text = b64encode(data.as_slice());
                        let plain_text = b64encode(data_copy.as_slice());
                        GenerateDataKeyResponse {
                            KeyId: key_id,
                            CiphertextBlob: &cipher_text,
                            Plaintext: &plain_text,
                        }.to_string()
                    } else {
                        if key.encrypt_data(&mut data, request.EncryptionContext).is_err() {
                            error!("Key material missing");
                            return response.send_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "KMSInternalException",
                                "Key material missing",
                            );
                        }
                        let cipher_text = b64encode(data.as_slice());
                        GenerateDataKeyWithoutPlaintextResponse {
                            KeyId: key_id,
                            CiphertextBlob: &cipher_text,
                        }.to_string()
                    };
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn create_alias(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    if !is_valid_alias(alias) {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidAliasNameException",
                            "Invalid AliasName",
                        );
                    }

                    let key_id = request.TargetKeyId;
                    let mut key_store = match key_store.lock() {
                        Ok(key_store) => key_store,
                        Err(_) => return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "DependencyTimeoutException",
                            "Key store lock not available",
                        ),
                    };
                    if key_store.get_alias(alias, &authorisation).is_some() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "AlreadyExistsException",
                            "Alias already exists",
                        );
                    }
                    let key = match key_store.lookup(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if let KeyState::PendingDeletion(_) = key.state() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        );
                    }
                    let key_arn = key.arn().arn_str().to_owned();
                    key_store.save_alias(alias.to_owned(), key_arn, &authorisation);
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn list_aliases(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                        Some(marker) => match page_from_marker(marker) {
                            Ok(page) => page,
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
                    let key_filter: Box<Fn(&str) -> bool>;
                    if let Some(key_id) = key_id {
                        let key = match key_store.lookup(key_id, &authorisation) {
                            Some(key) => key,
                            None => return response.send_error(
                                StatusCode::BAD_REQUEST,
                                "NotFoundException",
                                "Key not found",
                            ),
                        };
                        let key_arn = key.arn().arn_str().to_owned();
                        key_filter = Box::new(move |arn| arn == key_arn);
                    } else {
                        key_filter = Box::new(|_| true);
                    }
                    let mut aliases: Vec<(String, String, String)> = key_store.authorised_aliases(&authorisation)
                        .filter(|(_, arn)| key_filter(arn))
                        .map(|(alias, arn)| (alias.to_owned(), AliasArn::from_authorisation(alias, &authorisation).to_string(), arn.to_owned()))
                        .collect();
                    drop(key_store);
                    let per_page = request.Limit.unwrap_or(1000);
                    let next_marker = match paginate(&mut aliases, current_page, per_page) {
                        Ok(next_marker) => next_marker,
                        Err(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "Invalid Marker",
                        ),
                    };
                    let next_marker = if next_marker.is_empty() {
                        None
                    } else {
                        Some(next_marker.as_str())
                    };
                    let output = ListAliasesResponse {
                        Aliases: aliases.iter().map(|(alias, alias_arn, key_arn)| {
                            Alias {
                                AliasArn: alias_arn,
                                AliasName: alias,
                                TargetKeyId: key_arn,
                            }
                        }).collect(),
                        Truncated: next_marker.is_some(),
                        NextMarker: next_marker,
                    };

                    response.send(output)
                })
        )
    }

    fn delete_alias(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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

                    let mut key_store = match key_store.lock() {
                        Ok(key_store) => key_store,
                        Err(_) => return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "DependencyTimeoutException",
                            "Key store lock not available",
                        ),
                    };
                    let result = key_store.delete_alias(alias, &authorisation);
                    drop(key_store);
                    match result {
                        Err(_) => response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Alias not found",
                        ),
                        Ok(_) => response.send(""),
                    }
                })
        )
    }

    fn update_alias(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    if !is_valid_alias(alias) {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidAliasNameException",
                            "Invalid AliasName",
                        );
                    }

                    let key_id = request.TargetKeyId;
                    let mut key_store = match key_store.lock() {
                        Ok(key_store) => key_store,
                        Err(_) => return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "DependencyTimeoutException",
                            "Key store lock not available",
                        ),
                    };
                    let key = match key_store.lookup(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if let KeyState::PendingDeletion(_) = key.state() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        );
                    }
                    let key_arn = key.arn().arn_str().to_owned();
                    if key_store.delete_alias(alias, &authorisation).is_err() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "AliasName not found",
                        );
                    }
                    key_store.save_alias(alias.to_owned(), key_arn, &authorisation);
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn set_enabled(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse, enabled: bool) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    match key.state() {
                        KeyState::Enabled | KeyState::Disabled => *key.state_mut() = if enabled { KeyState::Enabled } else { KeyState::Disabled },
                        _ => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key cannot be enabled/disabled",
                        ),
                    };
                    drop(key_store);

                    response.send("")
                })
        )
    }

    fn schedule_deletion(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    if days < 7 || days > 30 {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValue",
                            "PendingWindowInDays must be between 7 and 30",
                        );
                    }
                    let deletion_date = Utc::now() + OldDuration::days(i64::from(days));
                    let deletion_timestamp = datetime_to_timestamp(&deletion_date);
                    let deletion_state = KeyState::PendingDeletion(deletion_date);

                    let key_id = request.KeyId;
                    let mut key_store = match key_store.lock() {
                        Ok(key_store) => key_store,
                        Err(_) => return response.send_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "DependencyTimeoutException",
                            "Key store lock not available",
                        ),
                    };
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    match key.state() {
                        KeyState::Enabled | KeyState::Disabled | KeyState::PendingImport => *key.state_mut() = deletion_state,
                        KeyState::PendingDeletion(_) => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is pending deletion",
                        ),
                    };
                    let output = ScheduleKeyDeletionResponse {
                        KeyId: key.arn().arn_str(),  // AWS returns ARN not key id :/
                        DeletionDate: deletion_timestamp,
                    };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn cancel_deletion(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if let KeyState::PendingDeletion(_) = key.state() {
                        *key.state_mut() = if key.is_external() && !key.has_key_material() {
                            KeyState::PendingImport
                        } else {
                            KeyState::Disabled
                        };
                    } else {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is not scheduled for deletion",
                        );
                    }
                    let output = CancelKeyDeletionResponse { KeyId: key_id };
                    let output = output.to_string();
                    drop(key_store);

                    response.send(output)
                })
        )
    }


    fn rotation_status(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup(key_id, &authorisation) {
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
                            "KMSInvalidStateException",
                            "Key is external",
                        );
                    }
                    let output = GetKeyRotationStatusResponse { KeyRotationEnabled: key.rotates() };
                    drop(key_store);

                    response.send(output)
                })
        )
    }

    fn set_rotation(&self, request: KMSRequest<AP::Authorisation>, response: KMSResponse, rotates: bool) -> FutureResponse {
        let key_store = Arc::clone(&self.key_store);
        Box::new(
            request.body_loaded()
                .and_then(move |authorised_request| {
                    let (authorisation, body) = match authorised_request {
                        KMSAuthorisedRequest::Authorised {authorisation, body} => (authorisation, body),
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
                    let key = match key_store.lookup_mut(key_id, &authorisation) {
                        Some(key) => key,
                        None => return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "NotFoundException",
                            "Key not found",
                        ),
                    };
                    if *key.state() != KeyState::Enabled {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "DisabledException",
                            "Key is disabled",
                        );
                    }
                    if key.set_rotates(rotates).is_err() {
                        return response.send_error(
                            StatusCode::BAD_REQUEST,
                            "KMSInvalidStateException",
                            "Key is external",
                        );
                    }
                    drop(key_store);

                    response.send("")
                })
        )
    }
}

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

        match self.auth_provider.authorise(&mut request) {
            Ok(_) => (),
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

            "TrentService.CreateKey" => self.create_key(request, response),
            "TrentService.UpdateKeyDescription" => self.update_description(request, response),
            "TrentService.DescribeKey" => self.describe_key(request, response),
            "TrentService.ListKeys" => self.list_keys(request, response),

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

            "TrentService.EnableKey" => self.set_enabled(request, response, true),
            "TrentService.DisableKey" => self.set_enabled(request, response, false),

            "TrentService.ScheduleKeyDeletion" => self.schedule_deletion(request, response),
            "TrentService.CancelKeyDeletion" => self.cancel_deletion(request, response),

            "TrentService.EnableKeyRotation" => self.set_rotation(request, response, true),
            "TrentService.DisableKeyRotation" => self.set_rotation(request, response, false),
            "TrentService.GetKeyRotationStatus" => self.rotation_status(request, response),

            "CreateGrant" | "RetireGrant" | "RevokeGrant" | "ListGrants" | "ListRetirableGrants" |
            "GetKeyPolicy" | "PutKeyPolicy" | "ListKeyPolicies" |
            "CreateCustomKeyStore" | "UpdateCustomKeyStore" | "DeleteCustomKeyStore" | "DescribeCustomKeyStores" |
            "ConnectCustomKeyStore" | "DisconnectCustomKeyStore" => Box::new(
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
