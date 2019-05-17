//! Provides any request with a valid V4 Authorisation header but with a pre-set account id

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use chrono::{Datelike, DateTime, Utc};
use regex::Regex;
use ring::constant_time::verify_slices_are_equal;
use ring::digest::{self, digest};
use ring::hmac;
use time::Duration as OldDuration;

use crate::authorisation::{AuthorisationProvider, Authorisation, AuthorisationError};
use crate::authorisation::access_tokens::AccessToken;
use crate::request::KMSRequest;
use crate::key_store::{Arn, Key};


#[derive(Debug)]
pub struct HeaderV4AuthorisationProvider {
    accounts: HashMap<String, AccessToken>,
}

impl HeaderV4AuthorisationProvider {
    pub fn new(mut accounts: Vec<AccessToken>) -> HeaderV4AuthorisationProvider {
        let accounts: HashMap<String, AccessToken> = accounts
            .drain(..)
            .map(|access_token| (access_token.access_key().to_owned(), access_token))
            .collect();
        match accounts.len() {
            0 => error!("No auth tokens loaded"),
            count => info!("Loaded {} auth tokens", count),
        }
        HeaderV4AuthorisationProvider { accounts }
    }
}

impl AuthorisationProvider for HeaderV4AuthorisationProvider {
    type Authorisation = HeaderV4Authorisation;

    fn authorise(&self, request: &mut KMSRequest<HeaderV4Authorisation>) -> Result<(), AuthorisationError> {
        // e.g. AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160517/us-west-2/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=67ccaa73c1af7fe83973ce8139104d55f3bdcebee323d2f2e65996d99015ace2
        static SIGNATURE_PREFIX: &str = "AWS4-HMAC-SHA256";
        let date = request.header("x-amz-date")
            .map(String::from)
            .or_else(|| request.header("date")
                .and_then(|date| {
                    DateTime::parse_from_rfc2822(date)
                        .map(|date| date.format("%Y%m%dT%H%M%SZ").to_string())
                        .ok()
                })
            );
        let date = match date {
            Some(date) => date,
            None => {
                debug!("Missing X-Amz-Date or invalid Date header");
                return Err(AuthorisationError::Invalid);
            },
        };
        let header = match request.header("Authorization") {
            Some(header) => header.trim(),
            None => {
                debug!("Missing Authorization header");
                return Err(AuthorisationError::Invalid);
            },
        };
        if !header.starts_with(SIGNATURE_PREFIX) {
            debug!("Authorization header does not start with {}", SIGNATURE_PREFIX);
            return Err(AuthorisationError::InvalidSignature);
        }
        let mut scope: String;
        let token: String;
        let region: String;
        let auth_headers: HashMap<String, String> = header
            .split_whitespace()
            .skip(1)
            .map(|part| (part, part.find('=')))
            .filter(|(_, index)| index.is_some())
            .map(|(part, index)| part.split_at(index.unwrap()))
            .map(|(key, value)| (key.to_owned(), if !value.is_empty() {
                value[1..].trim_end_matches(',').to_owned()
            } else {
                String::new()
            }))
            .collect();
        match auth_headers.get("Credential") {
            Some(credential) => {
                let credentials: Vec<&str> = credential.split('/').collect();
                if credentials.len() != 5 || credentials[3] != "kms" || credentials[4] != "aws4_request" {
                    debug!("Authorization header Credential cannot be split");
                    return Err(AuthorisationError::InvalidSignature);
                }
                let date = credentials[1];
                if !is_nearby_date(date) {
                    debug!("Authorization header Credential's date is too far away");
                    return Err(AuthorisationError::InvalidSignature);
                }
                scope = credentials[1..].iter()
                    .fold(String::new(), |mut scope, &part| {
                        scope.push('/');
                        scope.push_str(part);
                        scope
                    });
                scope.remove(0);
                token = credentials[0].to_owned();
                region = credentials[2].to_owned();
            },
            None => {
                debug!("Authorization header Credential missing");
                return Err(AuthorisationError::InvalidSignature);
            },
        }
        let access_token = match self.accounts.get(token.as_str()) {
            Some(access_token) => access_token,
            None => {
                debug!("Unknown access token {} in Authorization header Credential", token);
                return Err(AuthorisationError::Invalid);
            },
        };

        let signature = match auth_headers.get("Signature") {
            Some(signature) => signature.to_owned(),
            None => {
                debug!("Authorization header Signature missing");
                return Err(AuthorisationError::InvalidSignature);
            },
        };

        let signed_headers: HashSet<String> = match auth_headers.get("SignedHeaders") {
            Some(signed_headers) => signed_headers.split(';').map(String::from).collect(),
            None => {
                debug!("Authorization header SignedHeaders missing");
                return Err(AuthorisationError::InvalidSignature);
            },
        };
        if !["host", "content-type"].iter().all(|&header| signed_headers.contains(header)) {
            debug!("Host or Content-Type headers missing");
            return Err(AuthorisationError::InvalidSignature);
        }
        let included_headers: HashSet<String> = request.headers()
            .keys()
            .map(|header| header.as_str().to_lowercase())
            .collect();
        if signed_headers.difference(&included_headers).count() != 0 {
            debug!("Authorization header SignedHeaders includes headers not sent");
            return Err(AuthorisationError::InvalidSignature);
        }
        let unsigned_header_count = included_headers.difference(&signed_headers)
            .filter(|&header| !IGNORED_HEADERS.contains(header.as_str()))
            .inspect(|&header| debug!("Unsigned header `{}` sent in request", header))
            .count();
        if unsigned_header_count != 0 {
            warn!("Unsigned headers sent in request");
        }

        let mut headers: Vec<String> = signed_headers.iter().cloned().collect();
        headers.sort();
        headers.iter_mut().for_each(|header| {
            let value = request.header(header.as_str()).unwrap().to_owned();
            header.push(':');
            header.push_str(&value);
        });
        let mut partial_canonical_request = format!("{}\n/\n", request.method().as_str());
        let query_str = request.uri().query().unwrap_or_default();
        let mut query_params: Vec<(&str, &str)> = if query_str.is_empty() {
            Vec::new()
        } else {
            query_str.split('&')
                .map(|part| {
                    let parts: Vec<&str> = part.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        (parts[0], parts[1])
                    } else {
                        (parts[0], "")
                    }
                })
                .collect()
        };
        query_params.sort();
        let canonical_query_str = query_params.iter().fold(String::new(), |mut query, &(key, value)| {
            query.push_str(key);
            query.push('=');
            query.push_str(value);
            query.push('&');
            query
        });
        partial_canonical_request.push_str(&canonical_query_str.trim_end_matches('&'));
        partial_canonical_request.push('\n');
        let mut partial_canonical_request = headers.iter().fold(partial_canonical_request, |mut headers, header| {
            headers.push_str(&normalise_header(header));
            headers.push('\n');
            headers
        });
        partial_canonical_request.push('\n');
        partial_canonical_request.push_str(&auth_headers["SignedHeaders"]);
        partial_canonical_request.push('\n');
        let partial_canonical_request = RefCell::new(partial_canonical_request);

        let mut partial_str_to_sign = String::from(SIGNATURE_PREFIX);
        partial_str_to_sign.push('\n');
        partial_str_to_sign.push_str(date.as_str());
        partial_str_to_sign.push('\n');
        partial_str_to_sign.push_str(scope.as_str());
        partial_str_to_sign.push('\n');
        let partial_str_to_sign = RefCell::new(partial_str_to_sign);

        let prefixed_secret_key = format!("AWS4{}", access_token.secret_key()).as_bytes().to_vec();
        let partial_signature = hmac_sign(prefixed_secret_key.as_slice(), &date.as_bytes()[..8]);
        let partial_signature = hmac_sign(partial_signature.as_ref(), region.as_bytes());
        let partial_signature = hmac_sign(partial_signature.as_ref(), b"kms");
        let partial_signature = hmac_sign(partial_signature.as_ref(), b"aws4_request");

        let authorisation = HeaderV4Authorisation {
            token, account_id: access_token.account_id().to_owned(), region,
            signature,
            partial_canonical_request, partial_str_to_sign, partial_signature
        };
        *request.authorisation_mut() = Some(authorisation);
        Ok(())
    }
}

lazy_static! {
    static ref ONE_DAY: OldDuration = OldDuration::days(1);

    static ref IGNORED_HEADERS: HashSet<String> = [
            "accept", "accept-encoding", "authorization", "content-length", "expect", "user-agent",
            "x-amz-content-sha256", "x-amzn-trace-id",
        ].iter()
        .map(|&header| header.to_owned())
        .collect();

    static ref RE_WHITESPACE: Regex = Regex::new(r"\s+").expect("cannot compile regex");
}

fn normalise_header(header: &str) -> Cow<str> {
    let header = header.trim();
    RE_WHITESPACE.replace_all(header, " ")
}

fn hex_bytes(data: &[u8]) -> String {
    // TODO: if values are always fixed length, might be more efficient to use a macro
    data.iter()
        .map(|byte| format!("{:02x}", byte))
        .fold(String::new(), |mut payload, s| {
            payload.push_str(s.as_str());
            payload
        })
}

fn hmac_sign(key_bytes: &[u8], data: &[u8]) -> hmac::Signature {
    let key = hmac::SigningKey::new(&digest::SHA256, key_bytes);
    hmac::sign(&key, data)
}

#[cfg(not(test))]
fn is_nearby_date(date: &str) -> bool {
    let mut allowed_dates = DateIterator { date: Utc::now() + *ONE_DAY, count: 3 };
    allowed_dates.any(|allowed_date| date == allowed_date.as_str())
}

#[cfg(test)]
#[inline]
fn is_nearby_date(date: &str) -> bool {
    date == "20190507"
}

struct DateIterator {
    date: DateTime<Utc>,
    count: usize,
}

impl Iterator for DateIterator {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.count > 0 {
            let date = format!("{}{:02}{:02}", self.date.year(), self.date.month(), self.date.day());
            self.date = self.date - *ONE_DAY;
            self.count -= 1;
            Some(date)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct HeaderV4Authorisation {
    token: String,
    account_id: String,
    region: String,

    signature: String,
    partial_canonical_request: RefCell<String>,
    partial_str_to_sign: RefCell<String>,
    partial_signature: hmac::Signature,
}

impl Authorisation for HeaderV4Authorisation {
    #[inline]
    fn account_id(&self) -> &str {
        &self.account_id
    }

    #[inline]
    fn region(&self) -> &str {
        &self.region
    }

    fn authorise_body(&self, body: &str) -> Result<(), AuthorisationError> {
        let mut canonical_request = self.partial_canonical_request.replace(String::default());
        let mut str_to_sign = self.partial_str_to_sign.replace(String::default());

        let body_digest = digest(&digest::SHA256, body.as_bytes());
        let body_digest = hex_bytes(body_digest.as_ref());
        canonical_request.push_str(body_digest.as_str());
        let canonical_signature = digest(&digest::SHA256, canonical_request.as_bytes());
        let canonical_signature = hex_bytes(canonical_signature.as_ref());
        str_to_sign.push_str(canonical_signature.as_str());
        let expected_signature = hmac_sign(self.partial_signature.as_ref(), str_to_sign.as_bytes());
        let expected_signature = hex_bytes(expected_signature.as_ref());

        verify_slices_are_equal(expected_signature.as_bytes(), self.signature.as_bytes())
            .map_err(|_| {
                debug!("Expected signature {} does not match provided {}", expected_signature, self.signature);
                AuthorisationError::InvalidSignature
            })
    }

    fn authorises_access(&self, key: &Key) -> Result<(), AuthorisationError> {
        if key.arn().region() == self.region() && key.arn().account_id() == self.account_id() {
            Ok(())
        } else {
            debug!("Authorisation region or account ID does not match key");
            Err(AuthorisationError::Unauthorised)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use http::Request;
    use hyper::body::Body;

    const BODY: &str = "{}";

    fn try_authorise(mut request: KMSRequest<HeaderV4Authorisation>) -> (KMSRequest<HeaderV4Authorisation>, Result<(), AuthorisationError>, Option<Result<(), AuthorisationError>>) {
        env_logger::try_init().unwrap_or(());
        let provider = HeaderV4AuthorisationProvider::new(vec![
            AccessToken::new(
                String::from("0000000"),
                String::from("AAAAAAAAAAAAAAAAAAAAA"),
                String::from("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
            ),
        ]);
        let parse_result = provider.authorise(&mut request);
        let signature_result = match request.authorisation_mut() {
            Some(authorisation) => Some(authorisation.authorise_body(BODY)),
            None => None,
        };
        (request, parse_result, signature_result)
    }

    #[test]
    fn authorised() {
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1:6767/")
            .header("Host", "127.0.0.1:6767")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "TrentService.ListKeys")
            .header("X-Amz-Date", "20190507T205908Z")
            // Authorization header generated by AWS cli tool
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AAAAAAAAAAAAAAAAAAAAA/20190507/eu-west-2/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=5abc48718cbd3d78db8ef313386dfae0b65005fb44fe1e7ba4d25575e359c7a0")
            .body(Body::from(BODY))
            .unwrap();
        let request = KMSRequest::new(request);
        let (mut request, parse_result, signature_result) = try_authorise(request);
        assert!(parse_result.is_ok());
        assert!(signature_result.is_some());
        assert!(signature_result.unwrap().is_ok());
        assert!(request.authorisation_mut().is_some());
        if let Some(authorisation) = request.authorisation_mut() {
            assert_eq!(authorisation.account_id(), "0000000");
            assert_eq!(authorisation.region(), "eu-west-2");
        }
    }

    #[test]
    fn unauthorised() {
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1:6767/")
            .header("Host", "127.0.0.1:6767")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "TrentService.ListKeys")
            .header("X-Amz-Date", "20190507T205908Z")
            // incorrect signature
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AAAAAAAAAAAAAAAAAAAAA/20190507/eu-west-2/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=5abc48718cbd3d78db8ef313386dfae0b65005fb44fe1e7ba4d25575e3000000")
            .body(Body::from(BODY))
            .unwrap();
        let request = KMSRequest::new(request);
        let (mut request, parse_result, signature_result) = try_authorise(request);
        assert!(parse_result.is_ok());
        assert!(signature_result.is_some());
        assert!(signature_result.unwrap().is_err());
        assert!(request.authorisation_mut().is_some());
    }

    #[test]
    fn incorrect() {
        let request = Request::builder()
            .method("POST")
            .uri("http://127.0.0.1:6767/")
            .header("Host", "127.0.0.1:6767")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "TrentService.ListKeys")
            // missing date
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AAAAAAAAAAAAAAAAAAAAA/20190507/eu-west-2/kms/aws4_request, SignedHeaders=content-type;host;x-amz-target, Signature=5abc48718cbd3d78db8ef313386dfae0b65005fb44fe1e7ba4d25575e359c7a0")
            .body(Body::from(BODY))
            .unwrap();
        let request = KMSRequest::new(request);
        let (mut request, parse_result, signature_result) = try_authorise(request);
        assert!(parse_result.is_err());
        assert!(signature_result.is_none());
        assert!(request.authorisation_mut().is_none());
    }

    #[test]
    fn date_iterator() {
        let mut dates = DateIterator { date: Utc.ymd(2019, 5, 5).and_hms(12, 0, 0) + *ONE_DAY, count: 3 };
        assert_eq!(dates.next().unwrap().as_str(), "20190506");
        assert_eq!(dates.next().unwrap().as_str(), "20190505");
        assert_eq!(dates.next().unwrap().as_str(), "20190504");
        assert!(dates.next().is_none());
    }
}
