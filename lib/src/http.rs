//! HTTP client implementation using curl.

use crate::error::Result;
use curl::easy::{Easy2, Handler, WriteError};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// HTTP request methods.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum HttpMethod {
    #[default]
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    /// Custom HTTP method (e.g., "CONNECT", "TRACE", or non-standard methods)
    Custom(String),
}

impl HttpMethod {
    /// Returns the method as an uppercase string.
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Custom(s) => s,
        }
    }

    /// Returns true if this method typically has a request body.
    pub fn has_body(&self) -> bool {
        matches!(
            self,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch | HttpMethod::Custom(_)
        )
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HttpMethod {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            _ => HttpMethod::Custom(s.to_uppercase()),
        })
    }
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl From<&String> for HttpMethod {
    fn from(s: &String) -> Self {
        s.as_str().into()
    }
}

impl From<String> for HttpMethod {
    fn from(s: String) -> Self {
        s.as_str().into()
    }
}

struct ResponseHandler {
    data: Vec<u8>,
    headers: HashMap<String, String>,
}

impl ResponseHandler {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            headers: HashMap::new(),
        }
    }
}

impl Handler for ResponseHandler {
    fn write(&mut self, data: &[u8]) -> std::result::Result<usize, WriteError> {
        self.data.extend_from_slice(data);
        Ok(data.len())
    }

    fn header(&mut self, header: &[u8]) -> bool {
        if let Ok(header_str) = std::str::from_utf8(header) {
            if let Some((key, value)) = header_str.split_once(':') {
                self.headers
                    .insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }
        true
    }
}

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
        // Use from_utf8_lossy to avoid unnecessary clone for valid UTF-8
        // We still need to allocate since we can't consume self
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
        Self {
            verbose: false,
            timeout: None,
            follow_redirects: false,
            user_agent: None,
            headers: Vec::new(),
        }
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
        let mut client = HttpClient::new()?;

        if self.verbose {
            client.set_verbose(true)?;
        }

        if let Some(timeout) = self.timeout {
            client.set_timeout(timeout)?;
        }

        if self.follow_redirects {
            client.set_follow_location(true)?;
        }

        if let Some(ref ua) = self.user_agent {
            client.set_user_agent(ua)?;
        }

        if !self.headers.is_empty() {
            client.set_headers(&self.headers)?;
        }

        Ok(client)
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HttpClient {
    curl: Easy2<ResponseHandler>,
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let handler = ResponseHandler::new();
        let curl = Easy2::new(handler);

        Ok(Self { curl })
    }

    pub fn set_headers(&mut self, headers: &[(String, String)]) -> Result<()> {
        let mut list = curl::easy::List::new();
        for (name, value) in headers {
            list.append(&format!("{name}: {value}"))?;
        }
        self.curl.http_headers(list)?;
        Ok(())
    }

    /// Set verbose mode
    pub fn set_verbose(&mut self, verbose: bool) -> Result<()> {
        self.curl.verbose(verbose)?;
        Ok(())
    }

    /// Set timeout
    pub fn set_timeout(&mut self, timeout_secs: u64) -> Result<()> {
        self.curl
            .timeout(std::time::Duration::from_secs(timeout_secs))?;
        Ok(())
    }

    /// Set follow redirects
    pub fn set_follow_location(&mut self, follow: bool) -> Result<()> {
        self.curl.follow_location(follow)?;
        Ok(())
    }

    /// Set user agent
    pub fn set_user_agent(&mut self, user_agent: &str) -> Result<()> {
        self.curl.useragent(user_agent)?;
        Ok(())
    }

    /// Perform a GET request
    pub fn get(&mut self, url: &str) -> Result<HttpResponse> {
        self.curl.url(url)?;
        self.curl.get(true)?;
        self.perform()
    }

    /// Perform a POST request with optional body
    pub fn post(&mut self, url: &str, body: Option<&[u8]>) -> Result<HttpResponse> {
        self.curl.url(url)?;
        self.curl.post(true)?;

        if let Some(data) = body {
            self.curl.post_field_size(data.len() as u64)?;
            self.curl.post_fields_copy(data)?;
        }

        self.perform()
    }

    /// Perform a request with the specified HTTP method and optional body.
    ///
    /// This method accepts any type that implements `Into<HttpMethod>`, including
    /// `&str` for convenience.
    pub fn request(
        &mut self,
        method: impl Into<HttpMethod>,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        let method = method.into();
        self.curl.url(url)?;

        match &method {
            HttpMethod::Get => {
                self.curl.get(true)?;
            }
            HttpMethod::Post => {
                self.curl.post(true)?;
                if let Some(data) = body {
                    self.curl.post_field_size(data.len() as u64)?;
                    self.curl.post_fields_copy(data)?;
                }
            }
            HttpMethod::Put => {
                self.curl.custom_request("PUT")?;
                if let Some(data) = body {
                    self.curl.post_field_size(data.len() as u64)?;
                    self.curl.post_fields_copy(data)?;
                }
            }
            HttpMethod::Patch => {
                self.curl.custom_request("PATCH")?;
                if let Some(data) = body {
                    self.curl.post_field_size(data.len() as u64)?;
                    self.curl.post_fields_copy(data)?;
                }
            }
            HttpMethod::Delete => {
                self.curl.custom_request("DELETE")?;
                if let Some(data) = body {
                    self.curl.post_field_size(data.len() as u64)?;
                    self.curl.post_fields_copy(data)?;
                }
            }
            HttpMethod::Head => {
                self.curl.nobody(true)?;
            }
            HttpMethod::Options => {
                self.curl.custom_request("OPTIONS")?;
            }
            HttpMethod::Custom(name) => {
                self.curl.custom_request(name)?;
                if let Some(data) = body {
                    self.curl.post_field_size(data.len() as u64)?;
                    self.curl.post_fields_copy(data)?;
                }
            }
        }

        self.perform()
    }

    /// Perform the request and return the response
    fn perform(&mut self) -> Result<HttpResponse> {
        self.curl.perform()?;

        let status_code = self.curl.response_code()?;

        let handler = self.curl.get_mut();

        // Take ownership of data instead of cloning
        let response = HttpResponse {
            status_code,
            headers: std::mem::take(&mut handler.headers),
            body: std::mem::take(&mut handler.data),
        };

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_from_str() {
        assert_eq!(HttpMethod::from("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from("POST"), HttpMethod::Post);
        assert_eq!(HttpMethod::from("PUT"), HttpMethod::Put);
        assert_eq!(HttpMethod::from("PATCH"), HttpMethod::Patch);
        assert_eq!(HttpMethod::from("DELETE"), HttpMethod::Delete);
        assert_eq!(HttpMethod::from("HEAD"), HttpMethod::Head);
        assert_eq!(HttpMethod::from("OPTIONS"), HttpMethod::Options);
    }

    #[test]
    fn test_http_method_from_str_case_insensitive() {
        assert_eq!(HttpMethod::from("get"), HttpMethod::Get);
        assert_eq!(HttpMethod::from("Get"), HttpMethod::Get);
        assert_eq!(HttpMethod::from("post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from("Post"), HttpMethod::Post);
        assert_eq!(HttpMethod::from("delete"), HttpMethod::Delete);
    }

    #[test]
    fn test_http_method_custom() {
        let method = HttpMethod::from("CONNECT");
        assert_eq!(method, HttpMethod::Custom("CONNECT".to_string()));

        let method = HttpMethod::from("TRACE");
        assert_eq!(method, HttpMethod::Custom("TRACE".to_string()));

        // Custom methods are uppercased
        let method = HttpMethod::from("custom");
        assert_eq!(method, HttpMethod::Custom("CUSTOM".to_string()));
    }

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Head.as_str(), "HEAD");
        assert_eq!(HttpMethod::Options.as_str(), "OPTIONS");
        assert_eq!(
            HttpMethod::Custom("CONNECT".to_string()).as_str(),
            "CONNECT"
        );
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(format!("{}", HttpMethod::Get), "GET");
        assert_eq!(format!("{}", HttpMethod::Post), "POST");
        assert_eq!(
            format!("{}", HttpMethod::Custom("TRACE".to_string())),
            "TRACE"
        );
    }

    #[test]
    fn test_http_method_has_body() {
        // Methods that typically have a body
        assert!(HttpMethod::Post.has_body());
        assert!(HttpMethod::Put.has_body());
        assert!(HttpMethod::Patch.has_body());
        assert!(HttpMethod::Custom("CUSTOM".to_string()).has_body());

        // Methods that typically don't have a body
        assert!(!HttpMethod::Get.has_body());
        assert!(!HttpMethod::Delete.has_body());
        assert!(!HttpMethod::Head.has_body());
        assert!(!HttpMethod::Options.has_body());
    }

    #[test]
    fn test_http_method_default() {
        assert_eq!(HttpMethod::default(), HttpMethod::Get);
    }

    #[test]
    fn test_http_method_parse() {
        let method: HttpMethod = "POST".parse().unwrap();
        assert_eq!(method, HttpMethod::Post);

        let method: HttpMethod = "put".parse().unwrap();
        assert_eq!(method, HttpMethod::Put);
    }

    #[test]
    fn test_http_method_equality() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
        assert_eq!(
            HttpMethod::Custom("FOO".to_string()),
            HttpMethod::Custom("FOO".to_string())
        );
        assert_ne!(
            HttpMethod::Custom("FOO".to_string()),
            HttpMethod::Custom("BAR".to_string())
        );
    }

    #[test]
    fn test_http_method_clone() {
        let method = HttpMethod::Post;
        let cloned = method.clone();
        assert_eq!(method, cloned);

        let custom = HttpMethod::Custom("TEST".to_string());
        let cloned_custom = custom.clone();
        assert_eq!(custom, cloned_custom);
    }

    #[test]
    fn test_http_method_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(HttpMethod::Get);
        set.insert(HttpMethod::Post);
        set.insert(HttpMethod::Get); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&HttpMethod::Get));
        assert!(set.contains(&HttpMethod::Post));
    }
}
