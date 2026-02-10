# purl

A curl-esque CLI for making HTTP requests that require payment. Designed for humans and agents alike.

## Installation

```bash
git clone https://github.com/stripe/purl
cd purl
cargo install --path cli
```

Requires [Rust](https://rustup.rs/). Ensure `~/.cargo/bin` is in your PATH.

## Quickstart

It is recommended to use a wallet dedicated for usage with purl.

```bash
# Set up your wallet
purl wallet add

# Preview payment without executing
purl --dry-run https://api.example.com/data

# Make a request
purl https://api.example.com/data

# Require confirmation before paying
purl --confirm https://api.example.com/data

# Understand payment requirements for a resource
purl inspect http://api.example.com/data

# See your balance
purl balance

# See and manage wallets
purl wallet list
```

## Usage

```
purl [OPTIONS] <URL>
purl <COMMAND>
```

Run `purl help` for all commands or `purl topics` for detailed documentation.

## Development

```bash
make build    # Build
make test     # Run tests
make release  # Build release binary
```
