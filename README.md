# purl

A curl-esque CLI for making HTTP requests that require payment. Designed for humans and agents alike.

## Installation

via Homebrew
```bash
brew install stripe/purl/purl
```

via source
```bash
git clone https://github.com/stripe/purl
cd purl
cargo install --locked --path cli
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

`-L` / `--location` follows HTTP redirects, but does not authorize payments to a
different origin (scheme, host, or effective port). Cross-origin payment requests
are rejected, including with `--confirm` or `--dry-run`. Request the intended
payment destination directly instead. This also applies to the library client;
applications relying on cross-origin paid redirects must use the destination URL.
Same-origin redirects and ordinary non-payment redirects continue to work.

## Development

```bash
make build    # Build
make test     # Run tests
make release  # Build release binary
```
