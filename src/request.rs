use futures::Stream;
use futures::future::{self, Future};
use hyper::{Request, Uri, Method, Body, Error as HyperError};
use hyper::header::{HeaderMap, AsHeaderName, HeaderValue};
use uuid::Uuid;

use super::error::KMSError;
use super::authorisation::Authorisation;

pub struct KMSRequest<A> where A: Authorisation {
    request: Request<Body>,
    authorisation: Option<A>,
    uuid: Uuid,
}

pub enum KMSAuthorisedRequest<A> where A: Authorisation {
    Authorised { authorisation: A, body: String },
    Unauthorised,
}

impl<A> KMSRequest<A> where A: Authorisation {
    pub fn new(request: Request<Body>) -> KMSRequest<A> {
        KMSRequest { request, authorisation: None, uuid: Uuid::new_v4() }
    }

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn uri(&self) -> &Uri {
        self.request.uri()
    }

    pub fn method(&self) -> &Method {
        self.request.method()
    }

    pub fn headers(&self) -> &HeaderMap<HeaderValue> {
        self.request.headers()
    }

    pub fn header<'a, T>(&'a self, header: T) -> Option<&'a str> where T: 'a + AsHeaderName {
        self.request.headers()
            .get(header)
            .and_then(|header| header.to_str().ok())
    }

    pub fn authorisation_mut(&mut self) -> &mut Option<A> {
        &mut self.authorisation
    }

    pub fn body_loaded(self) -> Box<Future<Item=KMSAuthorisedRequest<A>, Error=KMSError> + Send> {
        let authorisation = self.authorisation.expect("cannot load body without authorisation");
        let body = self.request.into_body();
        Box::new(
            body
                .fold(Vec::new(), |mut body, chunk| {
                    body.extend_from_slice(&*chunk);
                    future::ok::<_, HyperError>(body)
                })
                .and_then(|body| {
                    let body = String::from_utf8(body).or_else::<String, _>(|e| {
                        warn!("Cannot read UTF8 body: {}", e);
                        Ok(String::new())
                    }).unwrap();
                    future::ok((authorisation, body))
                })
                .map_err(From::from)
                .and_then(|(authorisation, body)| {
                    authorisation.authorise_body(body.as_str())
                        .map(|_| {
                            debug!("Authorised as {}", authorisation.account_id());
                            KMSAuthorisedRequest::Authorised { authorisation, body }
                        })
                        .or(Ok(KMSAuthorisedRequest::Unauthorised))
                })
        )
    }
}
