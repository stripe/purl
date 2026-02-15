//! HTTP request handling for the CLI
//!
//! This module provides the RequestContext type and related functionality
//! for building and executing HTTP requests.

use anyhow::{Context, Result};
use base64::Engine;
use purl_lib::x402::PaymentPayload;
use purl_lib::{HttpClient, HttpClientBuilder, HttpMethod, HttpResponse};

use crate::cli::Cli;

/// Context for making HTTP requests with optional payment headers
pub struct RequestContext {
    pub method: HttpMethod,
    pub body: Option<Vec<u8>>,
    pub cli: Cli,
}

impl RequestContext {
    /// Create a new request context from CLI arguments
    pub fn new(cli: Cli) -> Self {
        let (method, body) = get_request_method_and_body(&cli);
        Self { method, body, cli }
    }

    /// Build an HTTP client with the configured options
    pub fn build_client(&self, extra_headers: Option<&[(String, String)]>) -> Result<HttpClient> {
        let mut headers = self
            .cli
            .parse_headers()
            .map_err(|e| anyhow::anyhow!("Invalid header: {}", e))?;

        if should_use_json_content_type(&self.cli) {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }

        if let Some(extra) = extra_headers {
            headers.extend_from_slice(extra);
        }

        let mut builder = HttpClientBuilder::new()
            .verbose(self.cli.is_verbose())
            .follow_redirects(self.cli.follow_redirects)
            .headers(&headers);

        if let Some(timeout) = self.cli.get_timeout() {
            builder = builder.timeout(timeout);
        }

        if let Some(user_agent) = &self.cli.user_agent {
            builder = builder.user_agent(user_agent);
        }

        Ok(builder.build()?)
    }

    /// Execute an HTTP request
    pub async fn execute(
        &self,
        url: &str,
        extra_headers: Option<&[(String, String)]>,
    ) -> Result<HttpResponse> {
        let mut client = self.build_client(extra_headers)?;
        Ok(client
            .request(self.method.clone(), url, self.body.as_deref())
            .await?)
    }

    /// Execute an HTTP request with a payment header
    pub async fn execute_with_payment(
        &self,
        url: &str,
        payment_payload: &PaymentPayload,
    ) -> Result<HttpResponse> {
        let payload_json = serde_json::to_string(payment_payload)
            .context("Failed to serialize payment payload")?;
        let encoded_payload = base64::engine::general_purpose::STANDARD.encode(payload_json);

        // Use version-appropriate header name
        let header_name = payment_payload.payment_header_name();
        let headers = vec![(header_name.to_string(), encoded_payload)];
        self.execute(url, Some(&headers)).await
    }
}

/// Determine the HTTP method and body based on CLI flags
fn get_request_method_and_body(cli: &Cli) -> (HttpMethod, Option<Vec<u8>>) {
    // Get the body from --data or --json
    let body = cli
        .json
        .as_ref()
        .or(cli.data.as_ref())
        .map(|s| s.as_bytes().to_vec());

    // Determine method: explicit -X flag, or POST if body present, or GET
    let method = cli
        .method
        .as_ref()
        .map(HttpMethod::from)
        .unwrap_or_else(|| {
            if body.is_some() {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            }
        });

    (method, body)
}

fn is_json_data(data: &str) -> bool {
    let trimmed = data.trim();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

fn should_use_json_content_type(cli: &Cli) -> bool {
    if cli.json.is_some() {
        return true;
    }
    if let Some(data) = &cli.data {
        return is_json_data(data);
    }
    false
}
