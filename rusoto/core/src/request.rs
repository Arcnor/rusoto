//! AWS API requests.
//!
//! Wraps the `hyper` library to send PUT, POST, DELETE and GET requests.

//extern crate lazy_static;

use std::env;
use std::io::Error as IoError;
use std::error::Error;
use std::fmt;
use std::collections::HashMap;
use std::boxed::Box;

use futures::{Future, Stream};
use futures::future;
use hyper::Client;
use hyper::Chunk as HyperChunk;
use hyper::Request as HyperRequest;
use hyper::Error as HyperError;
use hyper::header::{Headers, UserAgent};
use hyper::StatusCode;
use hyper::Method;
use hyper::client::{Connect, HttpConnector};
use hyper_tls::HttpsConnector;
use tokio_core::reactor::Handle;

use log::LogLevel::Debug;

use signature::SignedRequest;

// Pulls in the statically generated rustc version.
include!(concat!(env!("OUT_DIR"), "/user_agent_vars.rs"));

// Use a lazy static to cache the default User-Agent header
// because it never changes once it's been computed.
lazy_static! {
    static ref DEFAULT_USER_AGENT: Vec<Vec<u8>> = vec![format!("rusoto/{} rust/{} {}",
            env!("CARGO_PKG_VERSION"), RUST_VERSION, env::consts::OS).as_bytes().to_vec()];
}

/// Stores the response from a HTTP request.
pub struct HttpResponse<B> {
    /// Status code of HTTP Request
    pub status: StatusCode,
    /// Contents of Response
    pub body: Box<Stream<Item=B, Error=HttpDispatchError> + Send>,
    /// Headers stored as <key(string):value(string)>
    pub headers: HashMap<String, String>,
}

#[derive(Debug, PartialEq)]
/// An error produced when invalid request types are sent.
pub struct HttpDispatchError {
    message: String,
}

impl Error for HttpDispatchError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for HttpDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<HyperError> for HttpDispatchError {
    fn from(err: HyperError) -> HttpDispatchError {
        HttpDispatchError { message: err.description().to_string() }
    }
}

impl From<IoError> for HttpDispatchError {
    fn from(err: IoError) -> HttpDispatchError {
        HttpDispatchError { message: err.description().to_string() }
    }
}

///Trait for implementing HTTP Request/Response
pub trait DispatchSignedRequest {
    /// TODO: docs
    type Chunk: Extend<<Self::Chunk as IntoIterator>::Item> + IntoIterator + Default + AsRef<[u8]>;
    /// Dispatch Request, and then return a Response
    fn dispatch(&self, request: SignedRequest) -> Box<Future<Item=HttpResponse<Self::Chunk>, Error=HttpDispatchError>>;
}

impl<C: Connect> DispatchSignedRequest for Client<C> {
    type Chunk = HyperChunk;
    fn dispatch(&self, request: SignedRequest) -> Box<Future<Item=HttpResponse<Self::Chunk>, Error=HttpDispatchError>> {
        let hyper_method = match request.method().as_ref() {
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            v => return Box::new(future::err(HttpDispatchError { message: format!("Unsupported HTTP verb {}", v) })),
        };

        // translate the headers map to a format Hyper likes
        let mut hyper_headers = Headers::new();
        for h in request.headers().iter() {
            hyper_headers.set_raw(h.0.to_owned(), h.1.to_owned());
        }

        // Add a default user-agent header if one is not already present.
        if !hyper_headers.has::<UserAgent>() {
            hyper_headers.set_raw("user-agent".to_owned(), DEFAULT_USER_AGENT.clone());
        }

        let mut final_uri = format!("{}://{}{}", request.scheme(), request.hostname(), request.canonical_path());
        if !request.canonical_query_string().is_empty() {
            final_uri = final_uri + &format!("?{}", request.canonical_query_string());
        }

        if log_enabled!(Debug) {
            let payload = match request.payload {
                Some(ref payload_bytes) => {
                    String::from_utf8(payload_bytes.to_owned())
                        .unwrap_or_else(|_| String::from("<non-UTF-8 data>"))
                }
                _ => "".to_owned(),
            };

            debug!("Full request: \n method: {}\n final_uri: {}\n payload: {}\nHeaders:\n",
                   hyper_method,
                   final_uri,
                   payload);
            for h in hyper_headers.iter() {
                debug!("{}:{}", h.name(), h.value_string());
            }
        }

        let mut hyper_request = HyperRequest::new(hyper_method, final_uri.parse().expect("error parsing uri"));
        *hyper_request.headers_mut() = hyper_headers;

        if let Some(payload_contents) = request.payload {
            hyper_request.set_body(payload_contents);
        }

        Box::new(self.request(hyper_request).map_err(|err| err.into()).map(|hyper_response| {
            let mut headers: HashMap<String, String> = HashMap::new();

            for header in hyper_response.headers().iter() {
                headers.insert(header.name().to_string(), header.value_string());
            }

            HttpResponse {
                status: hyper_response.status(),
                body: Box::new(hyper_response.body().map_err(|err| err.into())),
                headers: headers,
            }
        }))
    }
}

#[derive(Debug, PartialEq)]
/// An error produced when the user has an invalid TLS client
pub struct TlsError {
    message: String,
}

impl Error for TlsError {
    fn description(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Helper method for creating an http client with tls.
/// Makes a `hyper` client with `NativeTls` for HTTPS support.
pub fn default_tls_client(threads: usize, handle: &Handle) -> Result<Client<HttpsConnector<HttpConnector>>, TlsError> {
    let connector = match HttpsConnector::new(threads, handle) {
        Ok(connector) => connector,
        Err(tls_error) => {
            return Err(TlsError {
                message: format!("Couldn't create NativeTlsClient: {}", tls_error),
            })
        }
    };
    Ok(Client::configure().connector(connector).build(handle))
}

#[cfg(test)]
mod tests {
    use Region;
    use signature::SignedRequest;

    #[test]
    fn custom_region_http() {
        let a_region = Region::Custom("http://localhost".to_owned());
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("localhost", request.hostname());
    }

    #[test]
    fn custom_region_https() {
        let a_region = Region::Custom("https://localhost".to_owned());
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("localhost", request.hostname());
    }

    #[test]
    fn custom_region_with_port() {
        let a_region = Region::Custom("https://localhost:8000".to_owned());
        let request = SignedRequest::new("POST", "sqs", &a_region, "/");
        assert_eq!("localhost:8000", request.hostname());
    }
}
