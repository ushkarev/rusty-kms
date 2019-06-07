use futures::future::{self, FutureResult};
use http::response::Builder;
use hyper::{Response, StatusCode, Body};
use uuid::Uuid;

use crate::requests::KMSError;

pub struct KMSResponse {
    uuid: Uuid,
    action: Option<String>,
    builder: Builder,
}

impl KMSResponse {
    pub fn new(uuid: Uuid) -> KMSResponse {
        let mut builder = Response::builder();
        builder
            .header(hyper::header::SERVER, format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
            .header(hyper::header::CONTENT_TYPE, "application/x-amz-json-1.1")
            .header("x-amzn-RequestId", uuid.to_string());
        KMSResponse { builder, uuid, action: None }
    }

    pub fn action_mut(&mut self) -> &mut Option<String> {
        &mut self.action
    }

    fn log_response(&self, response: &Response<Body>) {
        let mut action = self.action.as_ref().map_or("Unknown", String::as_str);
        if action.starts_with("TrentService.") {
            action = &action[13..];
        }
        info!("{} => {} [{}]", action, response.status(), self.uuid);
    }

    pub fn send<T>(mut self, body: T) -> FutureResult<Response<Body>, KMSError> where T: Into<Body> {
        let response = self.builder
            .body(body.into())
            .unwrap();
        self.log_response(&response);
        future::ok(response)
    }

    pub fn send_error(mut self, status: StatusCode, kind: &str, message: &str) -> FutureResult<Response<Body>, KMSError> {
        let response = self.builder
            .status(status)
            .body(format!(r#"{{"__type": "{}", "message": "{}"}}"#, kind, message).into())
            .unwrap();
        self.log_response(&response);
        future::ok(response)
    }
}
