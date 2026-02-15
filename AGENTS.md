# AGENTS.md

Guidance for AI agents working with the purl codebase.

## Project Overview

**purl** is a curl-like CLI for making HTTP requests to payment-gated APIs using the x402 payment protocol. It supports EVM chains (Ethereum, Base, Polygon, etc.) and Solana.

## Repository Structure

```
purl/
├── cli/                    # CLI application (binary)
│   └── src/
│       ├── main.rs         # Entry point
│       ├── cli.rs          # Argument parsing (clap)
│       ├── request.rs      # HTTP request execution
│       ├── payment.rs      # Payment flow orchestration
│       ├── *_commands.rs   # Subcommand implementations
│       └── output.rs       # Display formatting
├── lib/                    # Core library (purl-lib)
│   └── src/
│       ├── client.rs       # High-level PurlClient API
│       ├── http.rs         # HTTP client wrapper
│       ├── protocol/       # Payment protocol abstraction
│       ├── x402/           # x402 protocol implementation
│       ├── providers/      # Blockchain providers (EVM, Solana)
│       ├── keystore/       # Wallet encryption/storage
│       ├── network.rs      # Network definitions
│       └── currency.rs     # Token/currency definitions
├── skills/                 # AI agent skill definitions
└── Formula/                # Homebrew formula
```

## Key Abstractions

### PaymentProtocol (lib/src/protocol/)
Trait for implementing payment protocols. Currently only x402 is implemented.

### PaymentProvider (lib/src/providers/)
Trait for blockchain-specific payment execution. Implementations:
- `EvmProvider` - Ethereum-compatible chains
- `SolanaProvider` - Solana network

Feature flags control which providers are compiled:
- `evm` - Enables EVM support (default)
- `solana` - Enables Solana support (default)

### PurlClient (lib/src/client.rs)
High-level API combining HTTP client, protocol handling, and payment execution.

## Development Commands

```bash
make build    # Debug build
make test     # Run tests
make check    # Format check + clippy + tests + build
make fmt      # Auto-format and fix lints
make release  # Release build
make install  # Install to ~/.cargo/bin
```

## Code Style

- Run `make fmt` before committing
- All warnings are errors (`-D warnings` in clippy)
- Use `thiserror` for error types
- Use `remain` for sorted match arms
- Prefer `anyhow::Result` in CLI, `PurlError` in library

## Testing

Tests live alongside source files. Run with `cargo test`.

Key test files:
- `lib/src/x402/*.rs` - Protocol parsing tests
- `lib/src/providers/*.rs` - Provider logic tests
- `cli/src/inspect_command/*.rs` - Command output tests

## Adding a New Network

1. Add network definition to `lib/src/network.rs` in the `networks()` function
2. Add currency/token to `lib/src/currency.rs` if needed
3. Ensure the provider (EVM/Solana) supports it

## Adding a New Payment Protocol

1. Create module under `lib/src/` (like `x402/`)
2. Implement `PaymentProtocol` trait from `lib/src/protocol/mod.rs`
3. Register in `lib/src/protocol/registry.rs`

## Common Patterns

### Error Handling
```rust
// Library code - use PurlError
use crate::error::{PurlError, Result};

// CLI code - use anyhow for context
use anyhow::{Context, Result};
result.context("failed to parse response")?;
```

### Feature-Gated Code
```rust
#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "solana")]
pub mod solana;
```

### Async Runtime
The project uses tokio. CLI entry point sets up the runtime:
```rust
#[tokio::main]
async fn main() { ... }
```

## Important Files

| File | Purpose |
|------|---------|
| `lib/src/client.rs` | Main API surface |
| `lib/src/protocol/mod.rs` | Protocol trait definition |
| `lib/src/payment_provider.rs` | Provider trait definition |
| `lib/src/x402/protocol.rs` | x402 implementation |
| `cli/src/cli.rs` | CLI argument definitions |
| `cli/src/payment.rs` | Payment flow logic |

## Environment Variables

- `PURL_PASSWORD` - Wallet decryption password
- `NO_COLOR` - Disable colored output
- `RUST_LOG` - Control log verbosity

## Configuration

User config lives at `~/.purl/config.toml`. See `purl.toml.example` for format.

Keystores are stored in `~/.purl/keystores/`.
