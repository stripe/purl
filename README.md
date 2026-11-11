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

## EVM payment authorization lifetime

For x402 v1 and v2 EVM payments, purl accepts authorization timeouts from 1 to
300 seconds. Timeouts outside this range are rejected, including in `--dry-run`;
purl does not clamp or rewrite the requested timeout. Servers requesting more
than 300 seconds must update their challenges; there is no client override.

The five-minute limit bounds future redeemability from the signing-time clock
reading. The existing ten-minute `validAfter` backdating allowance for clock skew
is unchanged. Once sent, an authorization can remain redeemable until expiry
even if the HTTP request fails. A failed request does not cancel the authorization.

## Development

```bash
make build    # Build
make test     # Run tests
make release  # Build release binary
```
