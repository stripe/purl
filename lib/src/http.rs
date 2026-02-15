//! HTTP client implementation using reqwest.

use crate::error::{PurlError, Result};
use std::collections::HashMap;
use std::time::Duration;

pub use reqwest::Method as HttpMethod;

#[derive(Debug)]
pub struct HttpResponse {
    pub status_code: u32,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Convert the response body to a UTF-8 string.
    ///
    /// # Errors
    /// Returns an error if the body is not valid UTF-8.
    pub fn body_string(&self) -> Result<String> {
        Ok(String::from_utf8(self.body.clone())?)
    }

    /// Check if this response indicates payment is required (HTTP 402).
    pub fn is_payment_required(&self) -> bool {
        self.status_code == 402
    }

    /// Get a header value by name (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Get the payment requirements JSON from either the PAYMENT-REQUIRED header (base64) or body.
    ///
    /// For x402 v2, payment requirements are sent in the PAYMENT-REQUIRED header (base64 encoded).
    /// For backwards compatibility with v1, this also falls back to the response body.
    ///
    /// # Errors
    /// Returns an error if the header is present but cannot be decoded, or if the body is not valid UTF-8.
    pub fn payment_requirements_json(&self) -> Result<String> {
        crate::x402::payment_requirements_json(self)
    }
}

/// Builder for configuring HTTP clients.
///
/// This provides a fluent API for setting up an HttpClient with various options.
#[derive(Default)]
#[must_use]
pub struct HttpClientBuilder {
    verbose: bool,
    timeout: Option<u64>,
    follow_redirects: bool,
    user_agent: Option<String>,
    headers: Vec<(String, String)>,
}

impl HttpClientBuilder {
    /// Create a new HTTP client builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable verbose output for debugging.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set request timeout in seconds.
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.timeout = Some(seconds);
        self
    }

    /// Enable following HTTP redirects.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Set custom User-Agent header.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Add a custom HTTP header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple headers at once.
    pub fn headers(mut self, headers: &[(String, String)]) -> Self {
        self.headers.extend_from_slice(headers);
        self
    }

    /// Build the configured HTTP client.
    pub fn build(self) -> Result<HttpClient> {
        let redirect_policy = if self.follow_redirects {
            reqwest::redirect::Policy::default()
        } else {
            reqwest::redirect::Policy::none()
        };

        let mut builder = reqwest::Client::builder().redirect(redirect_policy);

        if let Some(timeout) = self.timeout {
            builder = builder.timeout(Duration::from_secs(timeout));
        }

        if let Some(ref ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }

        let client = builder.build()?;

        let mut header_map = reqwest::header::HeaderMap::new();
        for (name, value) in &self.headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| PurlError::Http(e.to_string()))?;
            let value = reqwest::header::HeaderValue::from_str(value)
                .map_err(|e| PurlError::Http(e.to_string()))?;
            header_map.append(name, value);
        }

        Ok(HttpClient {
            client,
            headers: header_map,
            verbose: self.verbose,
        })
    }
}

pub struct HttpClient {
    client: reqwest::Client,
    headers: reqwest::header::HeaderMap,
    verbose: bool,
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        HttpClientBuilder::new().build()
    }

    /// Perform a GET request.
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.request(HttpMethod::GET, url, None).await
    }

    /// Perform a POST request with optional body.
    pub async fn post(&self, url: &str, body: Option<&[u8]>) -> Result<HttpResponse> {
        self.request(HttpMethod::POST, url, body).await
    }

    /// Perform a request with the specified HTTP method and optional body.
    pub async fn request(
        &self,
        method: HttpMethod,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        if self.verbose {
            eprintln!("> {} {}", method, url);
        }

        let mut req = self
            .client
            .request(method, url)
            .headers(self.headers.clone());

        if let Some(data) = body {
            req = req.body(data.to_vec());
        }

        let response = req.send().await?;
        let status_code = response.status().as_u16() as u32;

        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                let key = key.as_str().to_lowercase();
                headers
                    .entry(key)
                    .and_modify(|existing: &mut String| {
                        existing.push_str(", ");
                        existing.push_str(v);
                    })
                    .or_insert_with(|| v.to_string());
            }
        }

        if self.verbose {
            eprintln!("< {} {}", status_code, url);
        }

        let body = response.bytes().await?;

        Ok(HttpResponse {
            status_code,
            headers,
            body: body.to_vec(),
        })
    }
}

