//! HTTP backchannel client abstraction.
//!
//! See `docs/rfcs/RFC-001-architecture.md` §6. Identical in shape to
//! `arctic-oauth::HttpClient`. Only used for artifact resolution (SOAP POST),
//! backchannel SLO (SOAP POST), and explicit metadata-fetch helpers — the
//! Web-Browser-SSO redirect/POST bindings never call this trait.

use std::future::Future;

/// Caller-supplied HTTP backchannel.
///
/// `fn send(...) -> impl Future + Send` (Rust 2024 edition AFIT) — no
/// `async-trait`, no `Box<dyn Future>` indirection.
pub trait HttpClient: Send + Sync + Sized {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send;
}

/// Outbound HTTP request emitted by the library and dispatched by the caller's
/// `HttpClient` implementation.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: http::Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP response handed back to the library by the caller's `HttpClient`
/// implementation.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// --- Optional reqwest-backed impl --------------------------------------------

#[cfg(feature = "reqwest-client")]
mod reqwest_impl {
    use super::*;

    /// `HttpClient` implementation backed by `reqwest`.
    ///
    /// The wrapped `reqwest::Client` is `pub` so callers that already hold a
    /// configured client (proxies, TLS settings, connection pooling) can hand
    /// it in directly: `ReqwestClient(my_existing_client)`.
    #[derive(Debug, Clone)]
    pub struct ReqwestClient(pub reqwest::Client);

    impl Default for ReqwestClient {
        fn default() -> Self {
            Self(reqwest::Client::new())
        }
    }

    impl HttpClient for ReqwestClient {
        fn send(
            &self,
            request: HttpRequest,
        ) -> impl Future<
            Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
        > + Send {
            let client = self.0.clone();
            async move {
                // `reqwest::Method` is a re-export of `http::Method` in
                // reqwest 0.12, so the conversion is a move. Going through
                // `from_bytes` keeps the code valid even if reqwest later
                // forks its method type.
                let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())?;

                let mut req = client.request(method, &request.url).body(request.body);
                for (name, value) in &request.headers {
                    req = req.header(name, value);
                }

                let resp = req.send().await?;

                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_owned(),
                            v.to_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect();
                let body = resp.bytes().await?.to_vec();

                Ok(HttpResponse {
                    status,
                    headers,
                    body,
                })
            }
        }
    }
}

#[cfg(feature = "reqwest-client")]
pub use reqwest_impl::ReqwestClient;

#[cfg(test)]
mod tests {
    use super::*;

    // A trivial in-memory client to prove the trait shape compiles and is
    // object-safe-in-spirit for generic plumbing.
    struct EchoClient;

    impl HttpClient for EchoClient {
        fn send(
            &self,
            request: HttpRequest,
        ) -> impl Future<
            Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>,
        > + Send {
            async move {
                Ok(HttpResponse {
                    status: 200,
                    headers: request.headers,
                    body: request.body,
                })
            }
        }
    }

    #[test]
    fn http_request_round_trip_fields() {
        let req = HttpRequest {
            method: http::Method::POST,
            url: "https://example.test/saml/artifact".into(),
            headers: vec![("Content-Type".into(), "text/xml".into())],
            body: b"<soap/>".to_vec(),
        };
        assert_eq!(req.method, http::Method::POST);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.body, b"<soap/>");
    }

    #[tokio::test]
    async fn echo_client_runs_in_executor() {
        let client = EchoClient;
        let req = HttpRequest {
            method: http::Method::GET,
            url: "x".into(),
            headers: vec![],
            body: b"hello".to_vec(),
        };
        let resp = client.send(req).await.expect("echo");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
    }
}
