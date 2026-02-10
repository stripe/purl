//! Exit codes for the purl CLI.
//!
//! Following standard Unix conventions and providing specific codes
//! for different error categories to aid scripting and automation.

/// Exit codes for the purl CLI.
///
/// These codes follow Unix conventions where possible:
/// - 0: Success
/// - 1: General error
/// - 2: Misuse of shell command (e.g., invalid arguments)
/// - 130: Script terminated by Ctrl+C (128 + SIGINT)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Successful execution
    Success = 0,

    /// General/unknown error
    GeneralError = 1,

    /// Invalid usage (bad arguments, invalid flags)
    InvalidUsage = 2,

    /// Configuration error (missing config, invalid config)
    ConfigError = 3,

    /// Network/connection error
    NetworkError = 4,

    /// Payment declined or failed
    PaymentFailed = 5,

    /// Insufficient funds for payment
    InsufficientFunds = 6,

    /// User cancelled operation (e.g., declined confirmation)
    UserCancelled = 7,

    /// Authentication/signing error
    AuthError = 8,

    /// Resource not found (network, wallet, etc.)
    NotFound = 9,

    /// Operation timed out
    Timeout = 10,

    /// Interrupted by signal (Ctrl+C)
    /// Standard Unix convention: 128 + signal number (SIGINT = 2)
    Interrupted = 130,
}

impl ExitCode {
    /// Convert to process exit code
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Exit the process with this code
    pub fn exit(self) -> ! {
        std::process::exit(self.code())
    }
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code.code()
    }
}

impl From<&anyhow::Error> for ExitCode {
    fn from(err: &anyhow::Error) -> Self {
        // Try to downcast to PurlError for specific handling
        if let Some(purl_err) = err.downcast_ref::<purl_lib::PurlError>() {
            return ExitCode::from(purl_err);
        }

        // Check error message for common patterns
        let msg = err.to_string().to_lowercase();

        if msg.contains("timeout") {
            ExitCode::Timeout
        } else if msg.contains("connection") || msg.contains("network") {
            ExitCode::NetworkError
        } else if msg.contains("config") {
            ExitCode::ConfigError
        } else if msg.contains("not found") {
            ExitCode::NotFound
        } else {
            ExitCode::GeneralError
        }
    }
}

impl From<&purl_lib::PurlError> for ExitCode {
    fn from(err: &purl_lib::PurlError) -> Self {
        use purl_lib::PurlError;

        match err {
            // Configuration errors
            PurlError::ConfigMissing(_)
            | PurlError::InvalidConfig(_)
            | PurlError::NoConfigDir
            | PurlError::TomlParse(_)
            | PurlError::TomlSerialize(_) => ExitCode::ConfigError,

            // Payment/funds errors
            PurlError::AmountExceedsMax { .. } | PurlError::InvalidAmount(_) => {
                ExitCode::InsufficientFunds
            }

            PurlError::NoPaymentMethods | PurlError::NoCompatibleMethod { .. } => {
                ExitCode::PaymentFailed
            }

            // Network/provider errors
            PurlError::ProviderNotFound(_)
            | PurlError::UnknownNetwork(_)
            | PurlError::Http(_)
            | PurlError::Curl(_) => ExitCode::NetworkError,

            // Auth/signing errors
            PurlError::InvalidKey(_) | PurlError::Signing(_) | PurlError::InvalidAddress(_) => {
                ExitCode::AuthError
            }

            // Not found errors
            PurlError::TokenConfigNotFound { .. } => ExitCode::NotFound,

            // General errors
            _ => ExitCode::GeneralError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_values() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::GeneralError.code(), 1);
        assert_eq!(ExitCode::Interrupted.code(), 130);
    }

    #[test]
    fn test_exit_code_from_purl_error() {
        use purl_lib::PurlError;

        assert_eq!(
            ExitCode::from(&PurlError::ConfigMissing("test".into())),
            ExitCode::ConfigError
        );
        assert_eq!(
            ExitCode::from(&PurlError::NoPaymentMethods),
            ExitCode::PaymentFailed
        );
        assert_eq!(
            ExitCode::from(&PurlError::UnknownNetwork("test".into())),
            ExitCode::NetworkError
        );
    }
}
