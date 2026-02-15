//! purl-lib - Library for making payment-enabled HTTP requests
//!
//! This library provides the core functionality for handling payment protocols,
//! including payment provider abstractions, HTTP client, and configuration management.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod config;
pub mod constants;
pub mod crypto;
pub mod currency;
pub mod error;
pub mod http;
pub mod keystore;
pub mod negotiator;
pub mod network;
pub mod payment_provider;
pub mod permissions;
pub mod protocol;
pub mod providers;
pub mod signer;
pub mod utils;
pub mod x402;

pub use config::Config;
pub use error::{PurlError, Result};

pub mod client;
pub use client::PurlClient;

pub use config::{
    CustomNetwork, CustomToken, EvmConfig, PaymentMethod, SolanaConfig, WalletConfig,
};
pub use currency::{currencies, Currency};
pub use http::{HttpClient, HttpClientBuilder, HttpMethod, HttpResponse};
pub use network::{networks, ChainType, Network, NetworkInfo};
pub use x402::{PaymentPayload, PaymentRequirementsResponse, SettlementResponse};

pub use payment_provider::{BuiltinProvider, NetworkBalance, PaymentProvider, PROVIDER_REGISTRY};
pub use protocol::{
    PaymentChallenge, PaymentProtocol, PaymentReceipt, ProtocolRegistry, PROTOCOL_REGISTRY,
};
