//! Library API - high-level client for making payment-enabled HTTP requests
//!
//! This module provides the main entry point for making HTTP requests with automatic
//! payment protocol handling. It uses the protocol abstraction layer to support
//! multiple payment protocols.

use crate::config::Config;
use crate::error::{PurlError, Result};
use crate::http::{HttpClient, HttpClientBuilder, HttpMethod, HttpResponse};
use crate::negotiator::PaymentNegotiator;
use crate::payment_provider::PROVIDER_REGISTRY;
use crate::protocol::{CredentialPayload, PROTOCOL_REGISTRY};
use crate::x402::SettlementResponse;
use base64::Engine;

/// Builder for making payment-enabled HTTP requests.
///
/// This is the main entry point for making HTTP requests with automatic payment handling.
/// Requests that return a 402 Payment Required status will automatically detect the
/// payment protocol, negotiate payment requirements, and submit payment before
/// retrying the request.
///
/// # Example
/// ```no_run
/// # use purl_lib::{PurlClient, Config};
/// # async fn example() -> purl_lib::Result<()> {
/// let client = PurlClient::new()?
///     .max_amount("1000000")
///     .verbose();
///
/// let result = client.get("https://api.example.com/data").await?;
/// # Ok(())
/// # }
/// ```
pub struct PurlClient {
    config: Config,
    max_amount: Option<String>,
    allowed_networks: Vec<String>,
    headers: Vec<(String, String)>,
    timeout: Option<u64>,
    follow_redirects: bool,
    user_agent: Option<String>,
    verbose: bool,
    dry_run: bool,
}

impl PurlClient {
    /// Create a new PurlClient by loading configuration from the default location.
    ///
    /// This loads the config from `~/.purl/config.toml`.
    ///
    /// # Errors
    /// Returns an error if the config file cannot be found or parsed.
    pub fn new() -> Result<Self> {
        let config = Config::load()?;
        Ok(Self::with_config(config))
    }

    /// Create a new PurlClient with the provided configuration.
    ///
    /// Use this when you want to provide configuration programmatically
    /// rather than loading it from a file.
    ///
    /// # Example
    /// ```no_run
    /// # use purl_lib::{PurlClient, Config, EvmConfig};
    /// # use std::path::PathBuf;
    /// let config = Config {
    ///     evm: Some(EvmConfig {
    ///         keystore: Some(PathBuf::from("/path/to/keystore.json")),
    ///     }),
    ///     solana: None,
    ///     ..Default::default()
    /// };
    /// let client = PurlClient::with_config(config);
    /// ```
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            max_amount: None,
            allowed_networks: Vec::new(),
            headers: Vec::new(),
            timeout: None,
            follow_redirects: false,
            user_agent: None,
            verbose: false,
            dry_run: false,
        }
    }

    /// Set the maximum amount (in token base units) willing to pay.
    ///
    /// If a payment request exceeds this amount, the request will fail
    /// with an `AmountExceedsMax` error.
    #[must_use]
    pub fn max_amount(mut self, amount: impl Into<String>) -> Self {
        self.max_amount = Some(amount.into());
        self
    }

    /// Restrict payments to only these networks.
    ///
    /// If specified, only payment requirements for these networks will be considered.
    /// Pass an empty slice to allow all networks.
    #[must_use]
    pub fn allowed_networks(mut self, networks: &[&str]) -> Self {
        self.allowed_networks = networks.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Add a custom HTTP header to all requests.
    ///
    /// Can be called multiple times to add multiple headers.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the HTTP request timeout in seconds.
    #[must_use]
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.timeout = Some(seconds);
        self
    }

    /// Enable automatic following of HTTP redirects.
    #[must_use]
    pub fn follow_redirects(mut self) -> Self {
        self.follow_redirects = true;
        self
    }

    /// Set a custom User-Agent header.
    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Enable verbose output for debugging.
    #[must_use]
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Enable dry-run mode.
    ///
    /// In dry-run mode, payment requirements are negotiated but no actual
    /// payment is made. Returns `PaymentResult::DryRun` with payment details.
    #[must_use]
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// Perform a GET request to the specified URL.
    ///
    /// If the server responds with 402 Payment Required, payment will be
    /// automatically negotiated and submitted before retrying the request.
    pub async fn get(&self, url: &str) -> Result<PaymentResult> {
        self.request(HttpMethod::GET, url, None).await
    }

    /// Perform a POST request to the specified URL with optional body data.
    ///
    /// If the server responds with 402 Payment Required, payment will be
    /// automatically negotiated and submitted before retrying the request.
    pub async fn post(&self, url: &str, data: Option<&[u8]>) -> Result<PaymentResult> {
        self.request(HttpMethod::POST, url, data).await
    }

    /// Configure a new HttpClient with the common settings
    fn configure_client(&self, additional_headers: &[(String, String)]) -> Result<HttpClient> {
        let mut builder = HttpClientBuilder::new()
            .verbose(self.verbose)
            .follow_redirects(self.follow_redirects)
            .headers(&self.headers)
            .headers(additional_headers);

        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }

        if let Some(ref ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }

        builder.build()
    }

    async fn request(&self, method: HttpMethod, url: &str, data: Option<&[u8]>) -> Result<PaymentResult> {
        let client = self.configure_client(&[])?;
        let response = client.request(method.clone(), url, data).await?;

        // Check if this is a payment-required response
        if !response.is_payment_required() {
            return Ok(PaymentResult::Success(response));
        }

        // Use protocol registry to find which protocol should handle this response
        let protocol = PROTOCOL_REGISTRY
            .find_handler(&response)
            .ok_or_else(|| PurlError::Http("No compatible payment protocol found".to_string()))?;

        // Parse the payment challenge using the detected protocol
        let json = protocol.parse_challenge_json(&response)?;
        let negotiator = PaymentNegotiator::new(&self.config)
            .with_allowed_networks(&self.allowed_networks)
            .with_max_amount(self.max_amount.as_deref());

        let selected = negotiator.select_requirement(&json)?;

        if self.dry_run {
            if let Some(provider) = PROVIDER_REGISTRY.find_provider(selected.network()) {
                let dry_run_info = provider.dry_run(&selected, &self.config)?;
                return Ok(PaymentResult::DryRun(dry_run_info));
            }
        }

        let provider = PROVIDER_REGISTRY
            .find_provider(selected.network())
            .ok_or_else(|| PurlError::ProviderNotFound(selected.network().to_string()))?;

        let payment_payload = provider.create_payment(&selected, &self.config).await?;

        let payload_json = serde_json::to_string(&payment_payload)?;
        let encoded_payload = base64::engine::general_purpose::STANDARD.encode(&payload_json);

        // Use protocol to create the credential header
        let credential = CredentialPayload {
            data: encoded_payload,
            version: payment_payload.x402_version,
        };
        let (header_name, header_value) = protocol.create_credential_header(&credential);
        let payment_header = vec![(header_name, header_value)];
        let client = self.configure_client(&payment_header)?;
        let response = client.request(method, url, data).await?;

        // Use protocol to parse the receipt
        let settlement = if let Some(receipt_json) =
            protocol.parse_receipt_json(&response, credential.version)?
        {
            let settlement: SettlementResponse = serde_json::from_str(&receipt_json)?;
            Some(settlement)
        } else {
            None
        };

        Ok(PaymentResult::Paid {
            response,
            settlement,
        })
    }
}

/// The result of an HTTP request that may have required payment.
#[derive(Debug)]
pub enum PaymentResult {
    Success(HttpResponse),
    Paid {
        response: HttpResponse,
        settlement: Option<SettlementResponse>,
    },

    /// Dry-run mode was enabled, so payment was not actually made.
    ///
    /// Contains information about what payment would have been made,
    /// including amount, asset, sender, recipient, and any warnings.
    DryRun(crate::payment_provider::DryRunInfo),
}
