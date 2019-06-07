#![deny(unused_must_use)]

#[macro_use]
extern crate log;

use base64::{decode as b64decode, encode as b64encode};
use chrono::{TimeZone, Utc};
use futures::future::{self};
use hyper::{Client, Request, Body, Method, Uri, Error};
use hyper::client::HttpConnector;
use hyper::header::HeaderValue;
use hyper::rt::{self, Future, Stream};
use serde_json::Value;

fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("demo=info")).init();

    let args = clap::App::new("Rusty KMS Demo").version(env!("CARGO_PKG_VERSION"))
        .arg(clap::Arg::with_name("endpoint")
            .help("Server address to connect to")
            .default_value("http://127.0.0.1:6767/"))
        .get_matches();
    let endpoint: Uri = args.value_of("endpoint").expect("endpoint not provided").parse().expect("cannot parse endpoint uri");

    warn!("This only works with open authorisation");
    rt::run(
        Demo::start(endpoint)
            .and_then(Demo::create_key)
            .and_then(Demo::generate_data_key)
            .and_then(Demo::decrypt_data_key)
            .and_then(Demo::delete_key)
            .and_then(Demo::describe_key)
            .map(|demo| {
                debug!("{:?}", demo);
            })
            .map_err(|error| {
                error!("Error: {}", error);
            })
    );
}

#[derive(Debug)]
enum Step {
    Start,
    CreatedKey(String),
    GeneratedEncryptedDataKey(Vec<u8>),
    DecryptedDataKey((String, Vec<u8>)),
    DeletedKey(String),
    Done,
}

#[derive(Debug)]
struct Demo {
    endpoint: Uri,
    client: Client<HttpConnector, Body>,
    step: Step,
}

type DemoFuture = Box<dyn Future<Item=Demo, Error=Error> + Send>;

impl Demo {
    fn make_request<T>(&self, action: &str, body: T) -> Request<Body> where T: Into<Body> {
        let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let action = format!("TrentService.{}", action);
        let mut request = Request::new(body.into());
        *request.method_mut() = Method::POST;
        *request.uri_mut() = self.endpoint.clone();
        let headers = request.headers_mut();
        headers.insert(
            hyper::header::USER_AGENT,
            HeaderValue::from_str(&format!("{}-demo/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))).unwrap(),
        );
        headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            "X-Amz-Target",
            HeaderValue::from_str(action.as_str()).unwrap(),
        );
        headers.insert(
            "X-Amz-Date",
            HeaderValue::from_str(now.as_str()).unwrap(),
        );
        request
    }

    fn start(endpoint: Uri) -> DemoFuture {
        info!("Connecting to Rusty KMS at {}", endpoint);
        let demo = Demo { endpoint, client: Client::new(), step: Step::Start };
        Box::new(future::ok(demo))
    }

    fn create_key(mut self) -> DemoFuture {
        if let Step::Start = &self.step {} else {
            unreachable!("step taken out of order");
        }
        let request = r#"{"Description": "Master key"}"#;
        let request = self.make_request("CreateKey", request);
        Box::new(
            self.client
                .request(request)
                .and_then(|response| {
                    response.into_body().concat2()
                })
                .map(|body| {
                    let body: Value = serde_json::from_slice(body.as_ref()).unwrap();
                    debug!("Response: {:?}", body);
                    let key_arn = body
                        .as_object().unwrap()
                        .get("KeyMetadata").expect("cannot read response")
                        .as_object().unwrap()
                        .get("Arn").unwrap()
                        .as_str().unwrap()
                        .to_owned();
                    info!("Created key `{}`", key_arn);
                    self.step = Step::CreatedKey(key_arn);
                    self
                })
        )
    }

    fn generate_data_key(mut self) -> DemoFuture {
        let key_arn = if let Step::CreatedKey(key_arn) = &self.step {
            key_arn
        } else {
            unreachable!("step taken out of order");
        };
        let request = format!(r#"{{"KeyId": "{}", "KeySpec": "AES_256", "EncryptionContext": {{"a": "123", "b": "abc"}}}}"#, key_arn);
        let request = self.make_request("GenerateDataKeyWithoutPlaintext", request);
        Box::new(
            self.client
                .request(request)
                .and_then(|response| {
                    response.into_body().concat2()
                })
                .map(|body| {
                    let body: Value = serde_json::from_slice(body.as_ref()).unwrap();
                    debug!("Response: {:?}", body);
                    let encrypted_key = body
                        .as_object().unwrap()
                        .get("CiphertextBlob").expect("cannot read response")
                        .as_str().unwrap();
                    let encrypted_key = b64decode(encrypted_key).unwrap();
                    info!("Encrypted data key created");
                    self.step = Step::GeneratedEncryptedDataKey(encrypted_key);
                    self
                })
        )
    }

    fn decrypt_data_key(mut self) -> DemoFuture {
        let encrypted_key = if let Step::GeneratedEncryptedDataKey(encrypted_key) = &self.step {
            encrypted_key
        } else {
            unreachable!("step taken out of order");
        };
        let encrypted_key = b64encode(encrypted_key.as_slice());
        let request = format!(r#"{{"CiphertextBlob": "{}", "EncryptionContext": {{"b": "abc", "a": "123"}}}}"#, encrypted_key);
        let request = self.make_request("Decrypt", request);
        Box::new(
            self.client
                .request(request)
                .and_then(|response| {
                    response.into_body().concat2()
                })
                .map(|body| {
                    let body: Value = serde_json::from_slice(body.as_ref()).unwrap();
                    debug!("Response: {:?}", body);
                    let body = body.as_object().unwrap();
                    let key_id = body
                        .get("KeyId").expect("cannot read response")
                        .as_str().unwrap()
                        .to_owned();
                    let data_key = body
                        .get("Plaintext").unwrap()
                        .as_str().unwrap();
                    let data_key = b64decode(data_key).unwrap();
                    info!("Decrypted data key of length {} with `{}`", data_key.len(), key_id);
                    self.step = Step::DecryptedDataKey((key_id, data_key));
                    self
                })
        )
    }

    fn delete_key(mut self) -> DemoFuture {
        let key_id = if let Step::DecryptedDataKey((key_id, _)) = &self.step {
            key_id.to_owned()
        } else {
            unreachable!("step taken out of order");
        };
        let request = format!(r#"{{"KeyId": "{}", "PendingWindowInDays": 7}}"#, key_id);
        let request = self.make_request("ScheduleKeyDeletion", request);
        Box::new(
            self.client
                .request(request)
                .and_then(|response| {
                    response.into_body().concat2()
                })
                .map(move |body| {
                    let body: Value = serde_json::from_slice(body.as_ref()).unwrap();
                    debug!("Response: {:?}", body);
                    let deletion_date = body
                        .as_object().unwrap()
                        .get("DeletionDate").expect("cannot read response")
                        .as_f64().unwrap()
                        .to_owned();
                    let deletion_date = deletion_date.trunc() as i64;
                    let deletion_date = Utc.timestamp_opt(deletion_date, 0).single().unwrap();
                    info!("Key `{}` will be deleted on {:?}", key_id, deletion_date);
                    self.step = Step::DeletedKey(key_id);
                    self
                })
        )
    }

    fn describe_key(mut self) -> DemoFuture {
        let key_id = if let Step::DeletedKey(key_id) = &self.step {
            key_id
        } else {
            unreachable!("step taken out of order");
        };
        let request = format!(r#"{{"KeyId": "{}"}}"#, key_id);
        let request = self.make_request("DescribeKey", request);
        Box::new(
            self.client
                .request(request)
                .and_then(|response| {
                    response.into_body().concat2()
                })
                .map(|body| {
                    let body: Value = serde_json::from_slice(body.as_ref()).unwrap();
                    let metadata = body
                        .as_object().unwrap()
                        .get("KeyMetadata").expect("cannot read response")
                        .as_object().unwrap();
                    info!("=== Done ===");
                    metadata.iter()
                        .map(|(key, value)| {
                            let value = match value {
                                Value::String(value) => value.to_owned(),
                                Value::Number(value) => {
                                    if key.ends_with("Date") {
                                        let date = value.as_i64().and_then(|value| Utc.timestamp_opt(value, 0).single());
                                        match date {
                                            Some(date) => format!("{:?}", date),
                                            _ => format!("{}", value)
                                        }
                                    } else {
                                        format!("{}", value)
                                    }
                                },
                                Value::Bool(value) => format!("{}", value),
                                Value::Null => String::new(),
                                Value::Object(_) | Value::Array(_) => unimplemented!(),
                            };
                            (key, value)
                        }).for_each(|(key, value)| {
                        if !value.is_empty() {
                            info!("{} = {}", key, value);
                        }
                    });
                    self.step = Step::Done;
                    self
                })
        )
    }
}
