//! In-memory `HttpClient` impl used by SOAP-bound tests. Records every request
//! it sees and serves a canned response.

#![expect(
    dead_code,
    reason = "mock client is shared across multiple integration-test binaries; \
              each binary only references a subset, so the unused-code lint \
              would otherwise fire spuriously per-binary."
)]

use std::future::Future;
use std::sync::Mutex;

use saml::http::{HttpClient, HttpRequest, HttpResponse};

/// Minimal mock for the `HttpClient` trait. Captures every request into
/// `recorded` (so tests can assert outbound shape) and replays the same
/// `canned_response` body for every call.
pub struct MockHttpClient {
    pub recorded: Mutex<Vec<HttpRequest>>,
    pub canned_response: Vec<u8>,
    pub canned_status: u16,
}

impl MockHttpClient {
    pub fn new(canned_response: Vec<u8>, canned_status: u16) -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            canned_response,
            canned_status,
        }
    }
}

impl HttpClient for MockHttpClient {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send
    {
        let body = self.canned_response.clone();
        let status = self.canned_status;
        // `PoisonError::into_inner` lets us keep recording on a poisoned mutex
        // — a poisoned lock here only means a *previous* test panicked between
        // lock acquisition and release, and recording the current request is
        // still the right thing to do.
        let mut guard = self
            .recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(request);
        drop(guard);
        async move {
            Ok(HttpResponse {
                status,
                headers: vec![],
                body,
            })
        }
    }
}
