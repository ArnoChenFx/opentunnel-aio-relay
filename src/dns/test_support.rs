//! Local HTTP server for provider tests. It records every request it receives
//! and answers with whatever the test's responder returns.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

use super::{BoxFuture, DnsProvider};

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    /// Path and query, exactly as received.
    pub target: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

pub struct MockServer {
    pub base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

/// Starts a server on a random local port. `respond` maps each request to a
/// status code and response body.
pub async fn serve<F>(respond: F) -> MockServer
where
    F: Fn(&Recorded) -> (u16, String) + Send + Sync + 'static,
{
    let requests = Arc::new(Mutex::new(Vec::new()));
    let respond = Arc::new(respond);
    let app = axum::Router::new().fallback({
        let requests = requests.clone();
        move |request: Request| {
            let requests = requests.clone();
            let respond = respond.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .unwrap_or_default()
                    .to_vec();
                let recorded = Recorded {
                    method: parts.method.to_string(),
                    target: parts
                        .uri
                        .path_and_query()
                        .map_or_else(String::new, |path| path.to_string()),
                    headers: parts.headers,
                    body,
                };
                let (status, text) = respond(&recorded);
                requests.lock().unwrap().push(recorded);
                (StatusCode::from_u16(status).unwrap(), text).into_response()
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    MockServer { base_url, requests }
}

/// Provider for tests that must never reach the DNS step.
pub struct NoDns;

impl DnsProvider for NoDns {
    fn create_txt<'a>(&'a self, _name: &'a str, _value: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { Err(anyhow!("this test has no DNS provider")) })
    }

    fn delete_txt<'a>(&'a self, _record_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
